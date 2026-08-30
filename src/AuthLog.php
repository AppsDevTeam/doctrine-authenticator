<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator;

use DateTimeImmutable;
use Doctrine\ORM\Mapping\Column;
use Doctrine\ORM\Mapping\Entity;
use Doctrine\ORM\Mapping\GeneratedValue;
use Doctrine\ORM\Mapping\Id;
use Doctrine\ORM\Mapping\Table;

/**
 * Append-only audit trail of authentication events (opt-in via
 * DoctrineAuthenticator::setAuthLog(true)).
 *
 * The entity exists only to describe the schema for migrations. Rows are
 * written through the underlying DBAL connection (see
 * DoctrineAuthenticator::writeAuthLog()), never through the ORM, and are
 * never updated. The table is meant to act as a transient staging buffer:
 * a project-side job is expected to move rows into a long-term audit store
 * (ordered by id, delete after a confirmed copy) - without such a job the
 * table grows indefinitely.
 */
#[Entity]
#[Table(name: "auth_log")]
class AuthLog
{
	public const TYPE_LOGIN = 'login';
	public const TYPE_LOGIN_FAILED = 'login_failed';
	public const TYPE_LOGIN_BLOCKED = 'login_blocked';
	public const TYPE_LOGOUT = 'logout';
	public const TYPE_FRAUD_DETECTED = 'fraud_detected';
	public const TYPE_INVALID_TOKEN = 'invalid_token';

	public const IDENTITY_MAX_LENGTH = 255;
	public const USER_AGENT_MAX_LENGTH = 500;
	public const REASON_MAX_LENGTH = 255;

	#[Id]
	#[Column(type: 'bigint')]
	#[GeneratedValue]
	protected ?string $id = null;

	#[Column(length: 30)]
	protected string $type;

	/** Login name as entered by the user - may reference a non-existent account */
	#[Column(nullable: true)]
	protected ?string $identity = null;

	#[Column(nullable: true)]
	protected ?string $objectClass = null;

	#[Column(nullable: true)]
	protected ?string $objectId = null;

	/** StorageEntity id - correlates login/logout/fraud events of one session */
	#[Column(nullable: true)]
	protected ?int $storageEntityId = null;

	#[Column(nullable: true)]
	protected ?string $context = null;

	#[Column(length: 45, nullable: true)]
	protected ?string $ip = null;

	#[Column(length: 500, nullable: true)]
	protected ?string $userAgent = null;

	/** Why the event happened - exception class for failures */
	#[Column(nullable: true)]
	protected ?string $reason = null;

	#[Column(type: 'json', nullable: true)]
	protected ?array $metadata = null;

	#[Column]
	protected DateTimeImmutable $createdAt;

	public function getId(): ?string
	{
		return $this->id;
	}

	public function getType(): string
	{
		return $this->type;
	}

	public function getIdentity(): ?string
	{
		return $this->identity;
	}

	public function getObjectClass(): ?string
	{
		return $this->objectClass;
	}

	public function getObjectId(): ?string
	{
		return $this->objectId;
	}

	public function getStorageEntityId(): ?int
	{
		return $this->storageEntityId;
	}

	public function getContext(): ?string
	{
		return $this->context;
	}

	public function getIp(): ?string
	{
		return $this->ip;
	}

	public function getUserAgent(): ?string
	{
		return $this->userAgent;
	}

	public function getReason(): ?string
	{
		return $this->reason;
	}

	public function getMetadata(): ?array
	{
		return $this->metadata;
	}

	public function getCreatedAt(): DateTimeImmutable
	{
		return $this->createdAt;
	}
}
