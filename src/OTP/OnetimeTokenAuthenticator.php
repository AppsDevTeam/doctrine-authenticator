<?php
declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

use ADT\DoctrineAuthenticator\DoctrineAuthenticator;
use ADT\DoctrineAuthenticator\DoctrineAuthenticatorIdentity;
use ADT\DoctrineComponents\EntityManager;
use Brick\PhoneNumber\PhoneNumber;
use Brick\PhoneNumber\PhoneNumberParseException;
use Nette\Http\Request;
use Nette\Security\AuthenticationException;
use Nette\Security\IIdentity;
use Nette\Security\Passwords;
use Nette\Security\UserStorage;
use Nette\Utils\Validators;

class OnetimeTokenAuthenticator extends DoctrineAuthenticator
{
	public function __construct(
		?string $expiration,
		UserStorage $cookieStorage,
		protected EntityManager $em,
		Request $httpRequest,
		protected OnetimeTokenService $onetimeTokenService,
		protected IdentityQueryFactory $identityQueryFactory,
	) {
		parent::__construct($expiration, $cookieStorage, $em, $httpRequest);
	}

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
			if (!$onetimeToken = $this->onetimeTokenService->findToken(OnetimeTokenTypeEnum::LOGIN, $user, markAsUsed: false)) {
				throw new AuthenticationException('Token ' . $user . ' not found.');
			}

			/** @var Identity $identity */
			if (!$identity = $this->em->getRepository($onetimeToken->getObjectClass())->find($onetimeToken->getObjectId())) {
				throw new AuthenticationException("Identity not found for token " . $onetimeToken->getId());
			}
		} else {
			/** @var Identity $identity */
			if (!$identity = $this->findIdentity($user, $context, $metadata)) {
				throw new AuthenticationException('Identity ' . $user . ' not found.');
			}

			if (
				!$this->verifyPassword($password, (string) $identity->getPassword())
				&&
				!$onetimeToken = $this->onetimeTokenService->findToken(OnetimeTokenTypeEnum::LOGIN, $password, $user, markAsUsed: false)
			) {
				throw new AuthenticationException('Wrong password for identifier ' . $user);
			}
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
		$identityQuery = $this->identityQueryFactory->create()
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
