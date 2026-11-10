<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\Tests\Entity;

use ADT\DoctrineAuthenticator\OTP\Identity;
use ADT\DoctrineAuthenticator\OTP\IdentityTrait;
use ADT\DoctrineComponents\Entities\Entity;
use ADT\DoctrineComponents\Entities\Traits\Identifier;
use Doctrine\ORM\Mapping as ORM;

/** Identita s heslem a jednorazovymi tokeny, jak ji dodava projekt nad OnetimeTokenAuthenticatorem. */
#[ORM\Entity]
#[ORM\Table(name: 'test_otp_user')]
class TestOtpUser implements Identity, Entity
{
	use Identifier;
	use IdentityTrait;

	#[ORM\Column(unique: true)]
	private string $email;

	#[ORM\Column(nullable: true)]
	private ?string $password;

	private string $authToken = '';

	private array $authMetadata = [];

	private ?string $context = null;

	public function __construct(string $email, ?string $password = null)
	{
		$this->email = $email;
		$this->password = $password;
	}

	public function getEmail(): string
	{
		return $this->email;
	}

	public function getPassword(): ?string
	{
		return $this->password;
	}

	public function getRoles(): array
	{
		return [];
	}

	public function getAuthObjectId(): string
	{
		return (string) $this->id;
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
