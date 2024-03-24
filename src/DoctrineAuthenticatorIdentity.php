<?php

namespace ADT\DoctrineAuthenticator;

use Nette\Security\IIdentity;

interface DoctrineAuthenticatorIdentity extends IIdentity
{
	public function getAuthObjectId(): string;
	public function getAuthToken(): ?string;
	public function setAuthToken(string $token): void;
	public function getAuthMetadata(): array;
	public function setAuthMetadata(array $metadata): void;
}
