<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\Tests\Entity;

use ADT\DoctrineAuthenticator\DoctrineAuthenticatorIdentity;
use Doctrine\ORM\Mapping as ORM;

/** Identita jako entita - wakeupIdentity() si ji dohledava v databazi podle session. */
#[ORM\Entity]
#[ORM\Table(name: 'test_user')]
class TestUser implements DoctrineAuthenticatorIdentity
{
	#[ORM\Id]
	#[ORM\Column]
	private string $id;

	private string $authToken = '';

	private array $authMetadata = [];

	private ?string $context = null;

	public function __construct(string $id)
	{
		$this->id = $id;
	}

	public function getId(): string
	{
		return $this->id;
	}

	public function getRoles(): array
	{
		return [];
	}

	public function getAuthObjectId(): string
	{
		return $this->id;
	}

	public function getAuthToken(): string
	{
		return $this->authToken;
	}

	public function setAuthToken(string $token): void
	{
		$this->authToken = $token;
	}

	public function getAuthMetadata(): array
	{
		return $this->authMetadata;
	}

	public function setAuthMetadata(array $metadata): void
	{
		$this->authMetadata = $metadata;
	}

	public function getContext(): ?string
	{
		return $this->context;
	}

	public function setContext(?string $context): static
	{
		$this->context = $context;

		return $this;
	}
}
