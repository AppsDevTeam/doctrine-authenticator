<?php

namespace ADT\DoctrineAuthenticator;

use Closure;
use DateTime;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Doctrine\ORM\Configuration;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Exception\ORMException;
use Doctrine\ORM\NonUniqueResultException;
use Doctrine\ORM\OptimisticLockException;
use Exception;
use Nette\Http\Request;
use Nette\Security\Authenticator;
use Nette\Security\IdentityHandler;
use Nette\Security\IIdentity;
use Nette\Security\SimpleIdentity;
use Nette\Security\UserStorage;
use Nette\Utils\Json;
use Nette\Utils\JsonException;
use Nette\Utils\Random;
use DateTimeImmutable;

abstract class DoctrineAuthenticator implements Authenticator, IdentityHandler
{
	private string $expiration;
	private UserStorage $cookieStorage;
	private Request $httpRequest;
	private Connection $connection;
	private Configuration $configuration;

	private EntityManagerInterface $em;

	private StorageEntity $storageEntity;
	
	private bool $fraudDetection = true;

	protected ?Closure $onInvalidToken = null;
	protected ?Closure $onFraudDetection = null;

	abstract protected function verifyCredentials(string $user, string $password, ?string $context = null, array $metadata = []): DoctrineAuthenticatorIdentity;
	abstract protected function findIdentityByCredentials(string $identifier, ?string $context = null, array $metadata = []): ?IIdentity;

	/**
	 * @throws Exception
	 */
	public function __construct(
		?string $expiration,
		UserStorage $cookieStorage,
		Connection $connection,
		Configuration $configuration,
		Request $httpRequest
	) {
		$this->expiration = $expiration;
		$this->httpRequest = $httpRequest;
		$this->connection = $connection;
		$this->configuration = $configuration;

		$this->em = $this->createEntityManager();

		$this->cookieStorage = $cookieStorage;
		$this->cookieStorage->setExpiration($expiration, false);
	}

	public function setFraudDetection(bool $fraudDetection): void
	{
		$this->fraudDetection = $fraudDetection;
	}

	/**
	 * @param DoctrineAuthenticatorIdentity $identity
	 * @throws Exception|ORMException
	 */
	public function sleepIdentity(IIdentity $identity): IIdentity
	{
		do {
			$token = Random::generate(32);

			$storageEntity = new StorageEntity($identity->getAuthObjectId(), $token);
			$storageEntity
				->setValidUntil(new DateTimeImmutable('+' . $this->expiration))
				->setIp($this->httpRequest->getRemoteAddress())
				->setUserAgent($this->httpRequest->getHeader('User-Agent'))
				->setContext($identity->getContext())
				->setMetadata($identity->getAuthMetadata());

			$this->em->persist($storageEntity);
			try {
				$this->em->flush();
				break;
			} catch (UniqueConstraintViolationException) {
				$this->em = $this->createEntityManager();
			}
		} while (true);

		$identity->setAuthToken($token);

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
		if (!$storageEntity = $this->findSession($identity->getId())) {
			if (!headers_sent()) {
				$this->cookieStorage->clearAuthentication(true);
			}
			if ($this->onInvalidToken) {
				($this->onInvalidToken)($identity->getId());
			}
			return null;
		}

		if ($storageEntity->getValidUntil() < new DateTime()) {
			if (!headers_sent()) {
				$this->cookieStorage->clearAuthentication(true);
			}
			return null;
		}

		// Token was probably stolen
		if (
			$this->fraudDetection
			&&
			$storageEntity->getIp() !== $this->httpRequest->getRemoteAddress()
			&&
			$storageEntity->getUserAgent() !== $this->httpRequest->getHeader('User-Agent')
		) {
			if (!headers_sent()) {
				$this->cookieStorage->clearAuthentication(true);
			}

			$storageEntity->setValidUntil(new DateTimeImmutable());
			$storageEntity->setFraudData($this->httpRequest->getRemoteAddress(), $this->httpRequest->getHeader('User-Agent'));
			$this->em->flush();

			if ($this->onFraudDetection) {
				($this->onFraudDetection)($storageEntity);
			}

			return null;
		}

		// Extend db token expiration and update IP and User Agent header
		$storageEntity->setIp($this->httpRequest->getRemoteAddress());
		$storageEntity->setUserAgent($this->httpRequest->getHeader('User-Agent'));
		$storageEntity->setValidUntil(new DateTimeImmutable('+' . $this->expiration));
		$this->em->flush();

		// Extend cookie expiration
		if (!headers_sent()) {
			$this->cookieStorage->saveAuthentication($identity);
		}

		$this->storageEntity = $storageEntity;

		$identity = $this->findIdentityByCredentials($storageEntity->getObjectId(), $storageEntity->getContext(), $storageEntity->getMetadata());
		$identity->setAuthToken($storageEntity->getToken());
		$this->initIdentity($identity, $storageEntity->getMetadata());
		return $identity;
	}

	/**
	 * @throws OptimisticLockException
	 * @throws ORMException
	 * @throws JsonException
	 */
	public function clearIdentity(int|SecurityUser $objectId, array $metadata = []): void
	{
		if (is_int($objectId)) {
			$qb = $this->em->getRepository(StorageEntity::class)
				->createQueryBuilder('e')
				->where('e.validUntil > :now')
				->setParameter('now', new DateTimeImmutable())
				->andWhere('e.objectId = :objectId')
				->setParameter('objectId', $objectId);
			if ($metadata) {
				$qb->andWhere('JSON_CONTAINS(e.metadata, :metadata) = 1')
					->setParameter('metadata', Json::encode($metadata));
			}
			/** @var StorageEntity $_session */
			foreach ($qb->getQuery()->getResult() as $_session) {
				$_session->setValidUntil(new DateTimeImmutable());
			}
		} else {
			$this->storageEntity->setValidUntil(new DateTimeImmutable());
		}
		$this->em->flush();
	}
	
	public function getStorageEntity(): StorageEntity
	{
		return $this->storageEntity;
	}
	
	protected function findSession(string $token): ?StorageEntity
	{
		return $this->em->getRepository(StorageEntity::class)
			->createQueryBuilder('e')
			->where('e.token = :token')
			->setParameter('token', $token)
			->getQuery()
			->getOneOrNullResult();
	}

	public function findIdentity(string $token): ?IIdentity
	{
		$storageEntity = $this->findSession($token);
		return $this->findIdentityByCredentials($storageEntity->getObjectId(), $storageEntity->getContext(), $storageEntity->getMetadata());
	}

	final public function authenticate(string $username, string $password, ?string $context = null, array $metadata = []): IIdentity
	{
		$user = $this->verifyCredentials($username, $password, $context, $metadata);
		$user->setAuthMetadata($metadata);
		return $user;
	}

	private function createEntityManager(): EntityManager
	{
		return new EntityManager(DriverManager::getConnection($this->connection->getParams()), $this->configuration);
	}

	protected function initIdentity(IIdentity $identity, array $metadata): void
	{
	}
}
