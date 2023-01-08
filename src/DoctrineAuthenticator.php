<?php

namespace ADT\DoctrineAuthenticator;

use Doctrine\DBAL\Connection;
use Doctrine\ORM\Configuration;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Exception\ORMException;
use Doctrine\ORM\NonUniqueResultException;
use Doctrine\ORM\OptimisticLockException;
use Exception;
use Nette\Bridges\SecurityHttp\CookieStorage;
use Nette\Http\Request;
use Nette\Security\Authenticator;
use Nette\Security\IdentityHandler;
use Nette\Security\IIdentity;
use Nette\Security\SimpleIdentity;
use Nette\Utils\Random;
use DateTimeImmutable;

abstract class DoctrineAuthenticator implements Authenticator, IdentityHandler
{
	private string $expiration;
	private CookieStorage $cookieStorage;
	private Request $httpRequest;

	private EntityManagerInterface $em;

	private StorageEntity $storageEntity;
	
	private bool $userAgentCheck = true;

	protected ?\Closure $onInvalidToken = null;

	abstract function getIdentity($id): ?IIdentity;

	/**
	 * @throws Exception
	 */
	public function __construct(
		?string $expiration,
		CookieStorage $cookieStorage,
		Connection $connection,
		Configuration $configuration,
		Request $httpRequest
	) {
		$this->expiration = $expiration;
		$this->httpRequest = $httpRequest;

		$this->em = EntityManager::create($connection->getParams(), $configuration);

		$this->cookieStorage = $cookieStorage;
		$this->cookieStorage->setExpiration($expiration, false);
	}

	public function setUserAgentCheck(bool $userAgentCheck)
	{
		$this->userAgentCheck = $userAgentCheck;
	}

	/**
	 * @param DoctrineAuthenticatorIdentity $identity
	 * @throws Exception
	 */
	public function sleepIdentity(IIdentity $identity): IIdentity
	{
		$token = self::generateToken();

		/** @var StorageEntity $storageEntity */
		$storageEntity = new StorageEntity($identity->getAuthObjectId(), $token);
		$storageEntity
			->setValidUntil(new DateTimeImmutable('+' . $this->expiration))
			->setIp($this->httpRequest->getRemoteAddress())
			->setUserAgent($this->httpRequest->getHeader('User-Agent'));
		$this->em->persist($storageEntity);
		$this->em->flush();

		$this->storageEntity = $storageEntity;

		return new SimpleIdentity($token);
	}

	/**
	 * @throws OptimisticLockException
	 * @throws ORMException
	 * @throws NonUniqueResultException
	 * @throws Exception
	 */
	public function wakeupIdentity(IIdentity $identity): ?IIdentity
	{
		/** @var StorageEntity $storageEntity */
		if (!$storageEntity = $this->em->getRepository(StorageEntity::class)
			->createQueryBuilder('e')
			->where('e.token = :token')
			->andWhere('e.validUntil >= :validUntil')
			->setParameters(['token' => $identity->getId(), 'validUntil' => new DateTimeImmutable()])
			->getQuery()
			->getOneOrNullResult()
		) {
			$this->cookieStorage->clearAuthentication(true);
			if ($this->onInvalidToken) {
				($this->onInvalidToken)($identity->getId());
			}
			return null;
		}

		// Token was probably stolen
		if ($this->userAgentCheck && $storageEntity->getUserAgent() !== $this->httpRequest->getHeader('User-Agent')) {
			$storageEntity->setValidUntil(new DateTimeImmutable());
			$storageEntity->setIsFraudDetected(true);
			$this->em->flush();
			return null;
		}

		// Extend db token expiration
		$storageEntity->setValidUntil(new DateTimeImmutable('+' . $this->expiration));
		$this->em->flush();

		// Extend cookie expiration
		$this->cookieStorage->saveAuthentication($identity);

		$this->storageEntity = $storageEntity;

		return $this->getIdentity($storageEntity->getObjectId());
	}

	/**
	 * @throws OptimisticLockException
	 * @throws ORMException
	 */
	public function clearIdentity()
	{
		$this->storageEntity->setValidUntil(new DateTimeImmutable());
		$this->em->flush();
	}
	
	public function getStorageEntity(): StorageEntity
	{
		return $this->storageEntity;
	}

	private static function generateToken(): string
	{
		return Random::generate(32);
	}
}
