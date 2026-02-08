<?php
declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

use DateTimeImmutable;
use Doctrine\ORM\Mapping\Column;

trait OnetimeTokenTrait
{
	#[Column(nullable: false)]
	protected string $token;

	#[Column(nullable: false)]
	protected string $type;

	#[Column(nullable: true)]
	protected ?int $objectId = null;

	#[Column(nullable: true)]
	protected ?string $objectClass = null;

	#[Column(nullable: true)]
	protected ?DateTimeImmutable $usedAt = null;

	#[Column(nullable: false)]
	protected DateTimeImmutable $validUntil;

	#[Column(nullable: false)]
	protected string $ipAddress;

	#[Column(nullable: true)]
	protected ?string $identifier = null;

	#[Column(nullable: false)]
	protected DateTimeImmutable $createdAt;

	public function __construct()
	{
		$this->createdAt = new DateTimeImmutable();
	}

	public function getToken(): string
	{
		return $this->token;
	}

	public function setToken(string $token): static
	{
		$this->token = $token;
		return $this;
	}

	public function getUsedAt(): ?DateTimeImmutable
	{
		return $this->usedAt;
	}

	public function setUsedAt(?DateTimeImmutable $usedAt): static
	{
		$this->usedAt = $usedAt;
		return $this;
	}

	public function setValidUntil(DateTimeImmutable $validUntil): static
	{
		$this->validUntil = $validUntil;
		return $this;
	}

	public function getValidUntil(): DateTimeImmutable
	{
		return $this->validUntil;
	}

	public function isValid(): bool
	{
		// Omezujeme jenom validitu u password Recovery
		if ($this->validUntil < (new DateTimeImmutable('now'))) {
			return false;
		}

		return true;
	}

	public function getType(): string
	{
		return $this->type;
	}

	public function setType(string $type): static
	{
		$this->type = $type;
		return $this;
	}

	public function getObjectId(): ?int
	{
		return $this->objectId;
	}

	public function setObjectId(?int $objectId): static
	{
		$this->objectId = $objectId;
		return $this;
	}

	public function getIpAddress(): string
	{
		return $this->ipAddress;
	}

	public function setIpAddress(string $ipAddress): static
	{
		$this->ipAddress = $ipAddress;
		return $this;
	}

	public function getObjectClass(): ?string
	{
		return $this->objectClass;
	}

	public function setObjectClass(?string $objectClass): static
	{
		$this->objectClass = $objectClass;
		return $this;
	}

	public function getIdentifier(): ?string
	{
		return $this->identifier;
	}

	public function setIdentifier(?string $identifier): static
	{
		$this->identifier = $identifier;
		return $this;
	}
}
