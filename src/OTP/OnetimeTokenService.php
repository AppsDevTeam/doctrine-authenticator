<?php
declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

use ADT\DoctrineComponents\Entities\Entity;
use ADT\DoctrineComponents\EntityManager;
use DateTimeImmutable;
use Exception;
use Nette\Utils\Random;
use ReflectionException;

class OnetimeTokenService
{
	private const int MAX_TOKENS_PER_IP = 5;
	private const string CHECK_TIMEFRAME = '-15 minutes';

	public function __construct(protected EntityManager $em)
	{
	}

	/**
	 * @throws ReflectionException
	 * @throws Exception
	 * @throws TooManyTokenAttemptsException
	 */
	public function saveToken(OnetimeTokenType $type, DateTimeImmutable $validUntil, ?Entity $entity = null, ?string $identifier = null, int $length = 32): string
	{
		$this->checkTokenLimit();

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
		$hashedToken = hash('sha256', $token);
		$now = new DateTimeImmutable();

		$qb = $this->em->createQueryBuilder();
		$qb->select('ot')
			->from($this->em->findEntityClassByInterface(OnetimeToken::class), 'ot')
			->where('ot.type = :type')
			->andWhere('ot.token = :token')
			->andWhere('ot.validUntil > :now')
			->andWhere('ot.usedAt IS NULL')
			->setParameter('type', $type->value)
			->setParameter('token', $hashedToken)
			->setParameter('now', $now);

		if ($identifier !== null) {
			$qb->andWhere('(ot.identifier = :identifier OR ot.identifier IS NULL)')
				->setParameter('identifier', $identifier);
		} else {
			$qb->andWhere('ot.identifier IS NULL');
		}

		/** @var OnetimeToken|null $onetimeToken */
		$onetimeToken = $qb->getQuery()->getOneOrNullResult();

		if ($onetimeToken && $markAsUsed) {
			$onetimeToken->setUsedAt(new DateTimeImmutable());
			$this->em->flush();
		}

		return $onetimeToken;
	}

	/**
	 * @throws TooManyTokenAttemptsException
	 */
	private function checkTokenLimit(): void
	{
		if (!isset($_SERVER['REMOTE_ADDR'])) {
			return;
		}

		$qb = $this->em->createQueryBuilder();
		$count = $qb->select('COUNT(ot.id)')
			->from($this->em->findEntityClassByInterface(OnetimeToken::class), 'ot')
			->where('ot.ipAddress = :ipAddress')
			->andWhere('ot.createdAt > :createdAfter')
			->setParameter('ipAddress', $_SERVER['REMOTE_ADDR'])
			->setParameter('createdAfter', new DateTimeImmutable(self::CHECK_TIMEFRAME))
			->getQuery()
			->getSingleScalarResult();

		if ($count >= self::MAX_TOKENS_PER_IP) {
			throw new TooManyTokenAttemptsException();
		}
	}
}