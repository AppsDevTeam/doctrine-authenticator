<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\Tests;

use ADT\DoctrineAuthenticator\DoctrineAuthenticatorIdentity;

/** Identita, kterou jinak dodava projekt; throttling se ji nedotyka, jen ji vraci. */
final class TestIdentity implements DoctrineAuthenticatorIdentity
{
	private string $authToken = '';
	private array $authMetadata = [];
	private ?string $context = null;

	public function __construct(private readonly string $username)
	{
	}

	public function getId(): string
	{
		return $this->username;
	}

	public function getRoles(): array
	{
		return [];
	}

	public function getAuthObjectId(): string
	{
		return $this->username;
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
