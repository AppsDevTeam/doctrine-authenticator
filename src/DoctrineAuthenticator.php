<?php

namespace ADT\DoctrineAuthenticator;

use Doctrine\DBAL\Connection;
use Doctrine\ORM\Configuration;
use Doctrine\ORM\EntityManagerInterface;
use Exception;
use Nette\Bridges\SecurityHttp\CookieStorage;
use Nette\Security\Authenticator;
use Nette\Security\IdentityHandler;
use Nette\Security\IIdentity;
use Nette\Security\SimpleIdentity;
use Nette\Security\UserStorage;
use Nette\Utils\Random;
use DateTimeImmutable;

abstract class DoctrineAuthenticator implements Authenticator, IdentityHandler
{
	private string $expiration;
	private string $storageEntityClass;
	protected CookieStorage $cookieStorage;
	private EntityManagerInterface $em;
	protected StorageEntity $storageEntity;

	abstract function getIdentity($id): IIdentity;
	
	/**
	 * @throws Exception
	 */
	public function __construct(
		string $expiration,
		string $storageEntityClass,
		CookieStorage $cookieStorage,
		Connection $connection,
		Configuration $configuration,
	) {
		if (!is_a($storageEntityClass, StorageEntity::class, true)) {
			throw new \Exception('Parameter "storageEntityClass" must be "' . StorageEntity::class . '" class.');
		}

		$this->expiration = $expiration;
		$this->storageEntityClass = $storageEntityClass;		
		$this->cookieStorage = $cookieStorage;
		$this->em = \Doctrine\ORM\EntityManager::create($connection->getParams(), $configuration);

		$this->cookieStorage->setExpiration($expiration, false);
	}

	/**
	 * @param DoctrineAuthenticatorIdentity $identity
	 * @throws Exception
	 */
	public function sleepIdentity(IIdentity $identity): IIdentity
	{
		$token = self::generateToken();

		/** @var StorageEntity $storageEntity */
		$storageEntity = new ($this->storageEntityClass)($identity->getAuthObjectId(), $token);
		$storageEntity
			->setValidUntil(new \DateTimeImmutable('+' . $this->expiration))
			->setIp($this->httpRequest->getRemoteAddress())
			->setUserAgent($this->httpRequest->getHeader('User-Agent'));
		$this->em->persist($storageEntity);
		$this->em->flush();

		return new SimpleIdentity($token);
	}

	public function wakeupIdentity(IIdentity $identity): ?IIdentity
	{
		/** @var StorageEntity $storageEntity */
		if (!$storageEntity = $this->em->getRepository($this->storageEntityClass)
			->createQueryBuilder('e')
			->where('e.token = :token')
			->andWhere('e.validUntil >= :validUntil')
			->setParameters(['token' => $identity->getId(), 'validUntil' => new \DateTime()])
			->getQuery()
			->getOneOrNullResult()
		) {
			return null;
		}

		// Token was probably stolen
		if ($storageEntity->getUserAgent() !== $this->httpRequest->getHeader('User-Agent')) {
			$storageEntity->setValidUntil(new DateTimeImmutable());
			$this->em->flush();
			return null;
		}

		// Extend the expiration
		$storageEntity->setValidUntil(new DateTimeImmutable('+' . $this->expiration));

		// Create a new token to reduce the risk of theft
		$token = self::generateToken();
		$storageEntity->setRegeneratedAt(new DateTimeImmutable());
		$storageEntity->setToken($token);
		$identity->setId($token);

		$this->em->flush();

		$this->cookieStorage->saveAuthentication($identity, false);
		
		$this->storageEntity = $storageEntity;
		
		return $this->getIdentity($storageEntity->getObjectId());
	}

	public function clearIdentity(SecurityUser $securityUser)
	{
		$this->storageEntity->setValidUntil(new DateTimeImmutable());
		$this->em->flush();
	}

	private static function generateToken(): string
	{
		return Random::generate(32);
	}
}
