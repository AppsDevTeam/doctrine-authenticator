<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator;

use DateTimeImmutable;
use Doctrine\ORM\Mapping\Column;
use Doctrine\ORM\Mapping\Entity;
use Doctrine\ORM\Mapping\GeneratedValue;
use Doctrine\ORM\Mapping\Id;
use Doctrine\ORM\Mapping\Index;
use Doctrine\ORM\Mapping\Table;
use Nette\Security\Resource;

#[Entity]
#[Table(name: "session")]
#[Index(name: "token_idx", fields: ["token"])]
class StorageEntity
{
	#[Id]
	#[Column]
	#[GeneratedValue]
	protected ?int $id;

	#[Column]
	protected DateTimeImmutable $createdAt;

	#[Column(length: 32)]
	protected string $objectId;

	#[Column(length: 32, unique: true)]
	protected string $token;

	#[Column(nullable: true)]
	protected ?string $context = null;

	#[Column]
	protected DateTimeImmutable $validUntil;

	#[Column(length: 15, nullable: true)]
	protected ?string $ip = null;

	#[Column(nullable: true)]
	protected ?string $userAgent = null;

	#[Column(type: 'json', nullable: true)]
	protected ?array $fraudData = null;

	#[Column(type: 'json', nullable: true)]
	protected ?array $metadata = null;

	protected ?string $contextEnum = null;

	public function __construct($objectId, string $token)
	{
		$this->createdAt = new DateTimeImmutable();
		$this->objectId = $objectId;
		$this->token = $token;
	}

	public function getObjectId(): string
	{
		return $this->objectId;
	}

	public function getToken(): string
	{
		return $this->token;
	}

	public function setToken(string $token): self
	{
		$this->token = $token;
		return $this;
	}

	public function getValidUntil(): ?DateTimeImmutable
	{
		return $this->validUntil;
	}

	public function setValidUntil(DateTimeImmutable $validUntil): self
	{
		$this->validUntil = $validUntil;
		return $this;
	}

	public function getIp(): ?string
	{
		return $this->ip;
	}

	public function setIp(?string $ip): self
	{
		$this->ip = $ip;
		return $this;
	}

	public function getUserAgent(): ?string
	{
		return $this->userAgent;
	}

	public function setUserAgent(?string $userAgent): self
	{
		$this->userAgent = $userAgent;
		return $this;
	}

	public function setFraudData(string $ip, string $userAgent): self
	{
		$this->fraudData = ['ip' => $ip, 'userAgent' => $userAgent];
		return $this;
	}

	public function getMetadata(): ?array
	{
		return $this->metadata;
	}

	public function setMetadata(?array $metadata): self
	{
		$this->metadata = $metadata;
		return $this;
	}

	public function getContext(): ?Resource
	{
		if ($this->contextEnum === null) {
			foreach (get_declared_classes() as $_class) {
				if (in_array(Resource::class, class_implements($_class))) {
					$this->contextEnum = $_class;
					return $this->contextEnum::from($this->context);
				}
			}
			throw new \Exception('Class ' . Resource::class . ' not implemented.');
		}
		return $this->contextEnum::from($this->context);
	}

	public function setContext(?Resource $context): self
	{
		$this->context = $context->getResourceId();
		return $this;
	}
}
