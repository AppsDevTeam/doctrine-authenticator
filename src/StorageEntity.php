<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator;

use ADT\DoctrineAuthenticator\DoctrineAuthenticatorIdentity;
use ADT\DoctrineAuthenticator\DoctrineAuthenticatorSession;
use App\Model\Entities\Attributes;
use App\Model\Entity\Identity;
use DateTimeImmutable;
use Exception;
use Doctrine\ORM\Mapping as ORM;
use Nette\Security\IIdentity;

abstract class StorageEntity
{
	/** @ORM\Column(type="datetime_immutable") */
	protected DateTimeImmutable $createdAt;

	/** @ORM\Column(type="string", length=32) */
	protected string $objectId;

	/** @ORM\Column(type="string", length=32) */
	protected string $token;

	/** @ORM\Column(type="datetime_immutable", nullable=true) */
	protected ?DateTimeImmutable $validUntil = null;

	/** @ORM\Column(type="datetime_immutable", nullable=true) */
	protected ?DateTimeImmutable $regeneratedAt = null;

	/** @ORM\Column(type="string", nullable=false) */
	protected string $ip;

	/** @ORM\Column(type="string", nullable=false) */
	protected string $userAgent;

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

	public function getRegeneratedAt(): ?DateTimeImmutable
	{
		return $this->regeneratedAt;
	}

	public function setRegeneratedAt(?DateTimeImmutable $regeneratedAt): self
	{
		$this->regeneratedAt = $regeneratedAt;
		return $this;
	}

	public function getIp(): string
	{
		return $this->ip;
	}

	public function setIp(string $ip): self
	{
		$this->ip = $ip;
		return $this;
	}

	public function getUserAgent(): string
	{
		return $this->userAgent;
	}

	public function setUserAgent(string $userAgent): self
	{
		$this->userAgent = $userAgent;
		return $this;
	}
}
