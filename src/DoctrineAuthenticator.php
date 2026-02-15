<?php

namespace ADT\DoctrineAuthenticator;

use Closure;
use DateTime;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
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

	private EntityManagerInterface $em;
	private EntityManagerInterface $internalEm;

	private StorageEntity $storageEntity;
	
	private bool $fraudDetection = true;

	protected ?Closure $onInvalidToken = null;
	protected ?Closure $onFraudDetection = null;

	abstract protected function verifyCredentials(string $user, ?string $password = null, ?string $context = null, array $metadata = []): DoctrineAuthenticatorIdentity;

	/**
	 * @throws Exception
	 */
	public function __construct(
		?string $expiration,
		UserStorage $cookieStorage,
		EntityManagerInterface $em,
		Request $httpRequest
	) {
		$this->expiration = $expiration;
		$this->httpRequest = $httpRequest;
		$this->em = $em;

		$this->internalEm = $this->createEntityManager();

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
				->setObjectClass(get_class($identity))
				->setMetadata($identity->getAuthMetadata());

			$this->internalEm->persist($storageEntity);
			try {
				$this->internalEm->flush();
				break;
			} catch (UniqueConstraintViolationException) {
				$this->internalEm = $this->createEntityManager();
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
		$token = $identity->getId();

		/** @var StorageEntity $storageEntity */
		if (!$storageEntity = $this->findSession($token)) {
			if (!headers_sent()) {
				$this->cookieStorage->clearAuthentication(true);
			}
			if ($this->onInvalidToken) {
				($this->onInvalidToken)($token);
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
			$this->internalEm->flush();

			if ($this->onFraudDetection) {
				($this->onFraudDetection)($storageEntity);
			}

			return null;
		}

		// Extend db token expiration and update IP and User Agent header
		$storageEntity->setIp($this->httpRequest->getRemoteAddress());
		$storageEntity->setUserAgent($this->httpRequest->getHeader('User-Agent'));
		$storageEntity->setValidUntil(new DateTimeImmutable('+' . $this->expiration));
		$this->internalEm->flush();

		// Extend cookie expiration
		if (!headers_sent()) {
			$this->cookieStorage->saveAuthentication($identity);
		}

		$this->storageEntity = $storageEntity;

		/** @var DoctrineAuthenticatorIdentity $identity */
		if (!$identity = $this->em->getRepository($storageEntity->getObjectClass())->find($storageEntity->getObjectId())) {
			return null;
		}
		$identity->setAuthToken($token);
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
			$qb = $this->internalEm->getRepository(StorageEntity::class)
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
		$this->internalEm->flush();
	}
	
	public function getStorageEntity(): StorageEntity
	{
		return $this->storageEntity;
	}
	
	protected function findSession(string $token): ?StorageEntity
	{
		return $this->internalEm->getRepository(StorageEntity::class)
			->createQueryBuilder('e')
			->where('e.token = :token')
			->setParameter('token', hash('sha256', $token))
			->getQuery()
			->getOneOrNullResult();
	}

	final public function authenticate(string $username, ?string $password = null, ?string $context = null, array $metadata = []): IIdentity
	{
		$user = $this->verifyCredentials($username, $password, $context, $metadata);
		$user->setAuthMetadata($metadata);
		return $user;
	}

	private function createEntityManager(): EntityManager
	{
		return new EntityManager(DriverManager::getConnection($this->em->getConnection()->getParams()), $this->em->getConfiguration());
	}

	protected function initIdentity(IIdentity $identity, array $metadata): void
	{
	}
}
