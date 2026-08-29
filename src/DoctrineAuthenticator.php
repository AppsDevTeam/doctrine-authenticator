<?php

namespace ADT\DoctrineAuthenticator;

use Closure;
use DateTime;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Types\Types;
use Doctrine\DBAL\Exception\UniqueConstraintViolationException;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Exception\ORMException;
use Doctrine\ORM\NonUniqueResultException;
use Doctrine\ORM\OptimisticLockException;
use Exception;
use Nette\Http\Request;
use Nette\Security\AuthenticationException;
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

	private bool $authLog = false;

	/** Login name from the current authenticate() call, for the subsequent sleepIdentity() */
	private ?string $authLogIdentity = null;

	private int $maxLoginAttempts = 0;
	private string $loginAttemptTimeout = '-15 minutes';

	protected ?Closure $onInvalidToken = null;
	protected ?Closure $onFraudDetection = null;
	private ?Closure $expirationCallback = null;

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
	 * Enables the append-only auth_log audit trail (see AuthLog). Opt-in:
	 * a project that enables it must also move rows away, otherwise the
	 * table grows indefinitely.
	 */
	public function setAuthLog(bool $authLog): void
	{
		$this->authLog = $authLog;
	}

	public function setExpirationCallback(Closure $callback): void
	{
		$this->expirationCallback = $callback;
	}

	private function getExpiration(?DoctrineAuthenticatorIdentity $identity = null): string
	{
		if ($this->expirationCallback && $identity) {
			try {
				$result = ($this->expirationCallback)($identity);
				if ($result !== null) {
					return $result;
				}
			} catch (\Throwable) {
				// Fall back to default expiration
			}
		}
		return $this->expiration;
	}

	public function setLoginAttemptProtection(int $maxAttempts, string $timeout = '-15 minutes'): void
	{
		$this->maxLoginAttempts = $maxAttempts;
		$this->loginAttemptTimeout = $timeout;
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
				->setValidUntil(new DateTimeImmutable('+' . $this->getExpiration($identity)))
				->setIp($this->httpRequest->getRemoteAddress())
				->setUserAgent($this->httpRequest->getHeader('User-Agent'))
				->setContext($identity->getContext())
				->setObjectClass(get_class($identity))
				->setMetadata($identity->getAuthMetadata());

			$this->internalEm->persist($storageEntity);
			$connection = $this->internalEm->getConnection();
			try {
				// Audit zapisujeme ve stejne transakci jako session - prihlaseni
				// bez auditniho zaznamu nesmi nastat (a naopak)
				$connection->beginTransaction();
				$this->internalEm->flush();
				$this->writeAuthLog(
					AuthLog::TYPE_LOGIN,
					identity: $this->authLogIdentity,
					objectClass: get_class($identity),
					objectId: (string) $identity->getAuthObjectId(),
					storageEntityId: $storageEntity->getId(),
					context: $identity->getContext(),
					metadata: $identity->getAuthMetadata() ?: null,
				);
				$connection->commit();
				break;
			} catch (UniqueConstraintViolationException) {
				if ($connection->isTransactionActive()) {
					$connection->rollBack();
				}
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
			// sha256 tokenu = hodnota sloupce session.token -> dohledatelna korelace
			$this->writeAuthLog(AuthLog::TYPE_INVALID_TOKEN, metadata: ['token' => hash('sha256', $token)]);
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
			$connection = $this->internalEm->getConnection();
			$connection->beginTransaction();
			$this->internalEm->flush();
			$this->writeAuthLog(
				AuthLog::TYPE_FRAUD_DETECTED,
				objectClass: $storageEntity->getObjectClass(),
				objectId: $storageEntity->getObjectId(),
				storageEntityId: $storageEntity->getId(),
				context: $storageEntity->getContext(),
				reason: 'IP and User-Agent mismatch',
			);
			$connection->commit();

			if ($this->onFraudDetection) {
				($this->onFraudDetection)($storageEntity);
			}

			return null;
		}

		$this->storageEntity = $storageEntity;

		/** @var DoctrineAuthenticatorIdentity $identity */
		if (!$realIdentity = $this->em->getRepository($storageEntity->getObjectClass())->find($storageEntity->getObjectId())) {
			return null;
		}
		$realIdentity->setAuthToken($token);
		$this->initIdentity($realIdentity, $storageEntity->getMetadata());

		// Extend db token expiration and update IP and User Agent header
		$storageEntity->setIp($this->httpRequest->getRemoteAddress());
		$storageEntity->setUserAgent($this->httpRequest->getHeader('User-Agent'));
		$storageEntity->setValidUntil(new DateTimeImmutable('+' . $this->getExpiration($realIdentity)));
		$this->internalEm->flush();

		// Extend cookie expiration
		if (!headers_sent()) {
			$this->cookieStorage->saveAuthentication($identity);
		}

		return $realIdentity;
	}

	/**
	 * @throws OptimisticLockException
	 * @throws ORMException
	 * @throws JsonException
	 */
	public function clearIdentity(int|string|null $objectId = null, array $metadata = []): void
	{
		$invalidated = [];
		if ($objectId) {
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
				$invalidated[] = $_session;
			}
		} else {
			$this->storageEntity->setValidUntil(new DateTimeImmutable());
			$invalidated[] = $this->storageEntity;
		}
		$connection = $this->internalEm->getConnection();
		$connection->beginTransaction();
		$this->internalEm->flush();
		foreach ($invalidated as $_session) {
			$this->writeAuthLog(
				AuthLog::TYPE_LOGOUT,
				objectClass: $_session->getObjectClass(),
				objectId: $_session->getObjectId(),
				storageEntityId: $_session->getId(),
				context: $_session->getContext(),
			);
		}
		$connection->commit();
	}
	
	public function getStorageEntity(): StorageEntity
	{
		return $this->storageEntity;
	}

	/**
	 * @return StorageEntity[]
	 */
	public function getActiveSessions(string $objectId): array
	{
		return $this->internalEm->getRepository(StorageEntity::class)
			->createQueryBuilder('e')
			->where('e.objectId = :objectId')
			->andWhere('e.validUntil > :now')
			->setParameter('objectId', $objectId)
			->setParameter('now', new DateTimeImmutable())
			->orderBy('e.createdAt', 'DESC')
			->getQuery()
			->getResult();
	}

	public function clearSession(int $sessionId): void
	{
		$session = $this->internalEm->getRepository(StorageEntity::class)->find($sessionId);
		if ($session) {
			$session->setValidUntil(new DateTimeImmutable());
			$connection = $this->internalEm->getConnection();
			$connection->beginTransaction();
			$this->internalEm->flush();
			$this->writeAuthLog(
				AuthLog::TYPE_LOGOUT,
				objectClass: $session->getObjectClass(),
				objectId: $session->getObjectId(),
				storageEntityId: $session->getId(),
				context: $session->getContext(),
			);
			$connection->commit();
		}
	}

	public function getCurrentSessionId(): ?int
	{
		return isset($this->storageEntity) ? $this->storageEntity->getId() : null;
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
		$this->authLogIdentity = $username;
		try {
			$this->checkLoginAttempts();
			$user = $this->verifyCredentials($username, $password, $context, $metadata);
		} catch (AuthenticationException $e) {
			$this->recordFailedLoginAttempt($username, $e, $context);
			throw $e;
		}

		$user->setAuthMetadata($metadata);
		return $user;
	}

	/**
	 * @throws TooManyLoginAttemptsException
	 */
	private function checkLoginAttempts(): void
	{
		if ($this->maxLoginAttempts <= 0) {
			return;
		}

		$ipAddress = $this->httpRequest->getRemoteAddress();
		if (!$ipAddress) {
			return;
		}

		// Attempts already rejected by the throttling are logged for auditing, but must not
		// be counted here - otherwise every blocked attempt would move the sliding window
		// and keep the address locked out for as long as the requests keep coming.
		$count = $this->internalEm->createQueryBuilder()
			->select('COUNT(la.id)')
			->from(LoginAttempt::class, 'la')
			->where('la.ipAddress = :ipAddress')
			->andWhere('la.createdAt > :createdAfter')
			->andWhere('(la.exception IS NULL OR la.exception != :throttledException)')
			->setParameter('ipAddress', $ipAddress)
			->setParameter('createdAfter', new DateTimeImmutable($this->loginAttemptTimeout))
			->setParameter('throttledException', TooManyLoginAttemptsException::class)
			->getQuery()
			->getSingleScalarResult();

		if ($count >= $this->maxLoginAttempts) {
			throw new TooManyLoginAttemptsException();
		}
	}

	private function recordFailedLoginAttempt(string $username, AuthenticationException $exception, ?string $context = null): void
	{
		$ipAddress = $this->httpRequest->getRemoteAddress();

		// LoginAttempt zustava vazany na throttling; auditni zaznam vznika vzdy
		$connection = $this->internalEm->getConnection();
		$connection->beginTransaction();
		if ($this->maxLoginAttempts > 0 && $ipAddress) {
			$loginAttempt = new LoginAttempt($ipAddress, $username, $exception);
			$this->internalEm->persist($loginAttempt);
			$this->internalEm->flush();
		}
		$this->writeAuthLog(
			$exception instanceof TooManyLoginAttemptsException ? AuthLog::TYPE_LOGIN_BLOCKED : AuthLog::TYPE_LOGIN_FAILED,
			identity: $username,
			context: $context,
			reason: get_class($exception),
		);
		$connection->commit();
	}

	/**
	 * Zapis auditni udalosti primym insertem pres DBAL (mimo ORM - zadna
	 * unit of work, zadne lifecycle eventy). Nazvy tabulky a sloupcu se
	 * berou z ClassMetadata, takze respektuji naming strategy projektu.
	 * Bezi na spojeni internalEm - volajici ji muze obalit transakci
	 * spolecne s flush() souvisejicich entit.
	 */
	private function writeAuthLog(
		string $type,
		?string $identity = null,
		?string $objectClass = null,
		?string $objectId = null,
		?int $storageEntityId = null,
		?string $context = null,
		?string $reason = null,
		?array $metadata = null,
	): void
	{
		if (!$this->authLog) {
			return;
		}

		$meta = $this->internalEm->getClassMetadata(AuthLog::class);
		$userAgent = $this->httpRequest->getHeader('User-Agent');

		$this->internalEm->getConnection()->insert(
			$meta->getTableName(),
			[
				$meta->getColumnName('type') => $type,
				// utocnik ovlada delku identity i User-Agentu - nikdy nesmi rozbit insert
				$meta->getColumnName('identity') => $identity !== null ? mb_substr($identity, 0, AuthLog::IDENTITY_MAX_LENGTH) : null,
				$meta->getColumnName('objectClass') => $objectClass,
				$meta->getColumnName('objectId') => $objectId,
				$meta->getColumnName('storageEntityId') => $storageEntityId,
				$meta->getColumnName('context') => $context,
				$meta->getColumnName('ip') => $this->httpRequest->getRemoteAddress(),
				$meta->getColumnName('userAgent') => $userAgent !== null ? mb_substr($userAgent, 0, AuthLog::USER_AGENT_MAX_LENGTH) : null,
				$meta->getColumnName('reason') => $reason !== null ? mb_substr($reason, 0, AuthLog::REASON_MAX_LENGTH) : null,
				$meta->getColumnName('metadata') => $metadata,
				$meta->getColumnName('createdAt') => new DateTimeImmutable(),
			],
			[
				$meta->getColumnName('storageEntityId') => Types::INTEGER,
				$meta->getColumnName('metadata') => Types::JSON,
				$meta->getColumnName('createdAt') => Types::DATETIME_IMMUTABLE,
			]
		);
	}

	private function createEntityManager(): EntityManager
	{
		return new EntityManager(DriverManager::getConnection($this->em->getConnection()->getParams()), $this->em->getConfiguration());
	}

	protected function initIdentity(IIdentity $identity, array $metadata): void
	{
	}
}
