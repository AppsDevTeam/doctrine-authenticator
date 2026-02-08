<?php
declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

use ADT\DoctrineAuthenticator\DoctrineAuthenticatorIdentity;
use ADT\DoctrineComponents\EntityManager;
use Brick\PhoneNumber\PhoneNumber;
use Brick\PhoneNumber\PhoneNumberParseException;
use Nette\Security\AuthenticationException;
use Nette\Security\IIdentity;
use Nette\Security\Passwords;
use Nette\Utils\Validators;

/**
 * @method Identity authenticate(string $user, string $password, ?string $context = null, array $metadata = []))
 */
trait OnetimeTokenAuthenticatorTrait
{
	abstract protected function getOnetimeTokenService(): OnetimeTokenService;
	abstract protected function getUniversalPasswords(): array;
	abstract protected function getIdentityQuery(): IdentityQuery;
	abstract protected function getEntityManager(): EntityManager;
	
	protected function verifyPassword(string $password, string $hash): bool
	{
		return new Passwords()->verify($password, $hash);
	}

	/**
	 * @throws AuthenticationException
	 */
	protected function verifyCredentials(string $user, ?string $password = null, ?string $context = null, array $metadata = []): DoctrineAuthenticatorIdentity
	{
		$onetimeToken = null;
		if (!$password) {
			/** @var OnetimeToken $onetimeToken */
			if (!$onetimeToken = $this->getOnetimeTokenService()->findToken(OnetimeTokenTypeEnum::LOGIN, $user, markAsUsed: false)) {
				throw new AuthenticationException();
			}

			/** @var Identity $identity */
			if (!$identity = $this->getEntityManager()->getRepository($onetimeToken->getObjectClass())->find($onetimeToken->getObjectId())) {
				throw new AuthenticationException();
			}
		} else {
			/** @var Identity $identity */
			if (!$identity = $this->findIdentity($user, $context, $metadata)) {
				throw new AuthenticationException('fcadmin.appGeneral.exceptions.wrongCredentials');
			}

			if (!array_any($this->getUniversalPasswords(), fn($universalPassword) => $this->verifyPassword($password, $universalPassword))) {
				if (
					!$this->verifyPassword($password, (string) $identity->getPassword())
					&&
					!$onetimeToken = $this->getOnetimeTokenService()->findToken(OnetimeTokenTypeEnum::LOGIN, $password, $user, markAsUsed: false)
				) {
					throw new AuthenticationException();
				}
			}
		}

		if (!$identity->getIsActive()) {
			throw new AuthenticationException();
		}

		$identity->setOnetimeToken($onetimeToken);

		$this->validateIdentity($identity, $context, $metadata);

		return $identity;
	}

	protected function initQueryObject(IdentityQuery $query, UserTypeEnum $userType, ?string $context = null, array $metadata = []): void
	{
	}

	public function findIdentity(string $identifier, ?string $context = null, array $metadata = []): ?IIdentity
	{
		$identityQuery = $this->getIdentityQuery()
			->byContext($context);

		if ($this->validatePhoneNumber($identifier)) {
			$identityQuery->byPhoneNumber($identifier);
			$userType = UserTypeEnum::PHONE;
		} elseif (Validators::isEmail($identifier)) {
			$identityQuery->byEmail($identifier);
			$userType = UserTypeEnum::EMAIL;
		} else {
			$identityQuery->byUsername($identifier);
			$userType = UserTypeEnum::USERNAME;
		}

		$this->initQueryObject($identityQuery, $userType, $context, $metadata);

		/** @var Identity $identity */
		$identity = $identityQuery->fetchOneOrNull();

		return $identity;
	}

	protected function validateIdentity(Identity $identity, ?string $context = null, array $metadata = []): void
	{
	}

	protected function validatePhoneNumber(string $phoneNumber): bool
	{
		try {
			if (!PhoneNumber::parse($phoneNumber)->isValidNumber()) {
				return false;
			}
		} catch (PhoneNumberParseException) {
			return false;
		}
		return true;
	}
}
