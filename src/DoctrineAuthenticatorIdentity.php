<?php

namespace ADT\DoctrineAuthenticator;

use Nette\Security\IIdentity;
use Nette\Security\Resource;

interface DoctrineAuthenticatorIdentity extends IIdentity
{
	public function getAuthObjectId(): string;

	public function getAuthToken(): string;
	public function setAuthToken(string $token): void;
	
	public function getAuthMetadata(): array;
	public function setAuthMetadata(array $metadata): void;
	
	public function getContext(): ?Resource;
	public function setContext(?Resource $context): void;
}
