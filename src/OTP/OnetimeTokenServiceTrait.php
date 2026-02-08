<?php
declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

use ADT\DoctrineComponents\Entities\Entity;
use ADT\DoctrineComponents\EntityManager;
use DateTimeImmutable;
use Exception;
use Nette\Utils\Random;
use ReflectionException;

trait OnetimeTokenServiceTrait
{
	public function __construct(protected EntityManager $em, protected OnetimeTokenQueryFactory $onetimeTokenQueryFactory)
	{
	}

	/**
	 * @throws ReflectionException
	 * @throws Exception
	 */
	public function saveToken(OnetimeTokenType $type, DateTimeImmutable $validUntil, ?Entity $entity = null, ?string $identifier = null, int $length = 32): string
	{
		$token = Random::generate($length, '123456789ABCDEFGHJKLMNPQRSTUVWXYZ');

		/** @var OnetimeToken $onetimeToken */
		$onetimeToken = new ($this->em->findEntityClassByInterface(OnetimeToken::class));
		$onetimeToken
			->setType($type->value)
			->setValidUntil($validUntil)
			->setObjectClass($entity ? $entity::class : null)
			->setObjectId($entity?->getId())
			->setIdentifier($identifier)
			->setToken(hash('sha256', $token))
			->setIpAddress($_SERVER['REMOTE_ADDR']);
		$this->em->persist($onetimeToken);
		$this->em->flush();

		return $token;
	}

	public function findToken(OnetimeTokenType $type, string $token, ?string $identifier = null, bool $markAsUsed = true): ?OnetimeToken
	{
		/** @var OnetimeToken $onetimeToken */
		if ($onetimeToken = $this->onetimeTokenQueryFactory->create()
			->byIsValid()
			->byType($type->value)
			->byIdentifier($identifier)
			->byToken(hash('sha256', $token))
			->fetchOneOrNull()
		) {
			if ($markAsUsed) {
				$onetimeToken->setUsedAt(new DateTimeImmutable());
				$this->em->flush();
			}
		}
		
		return $onetimeToken;
	}
}