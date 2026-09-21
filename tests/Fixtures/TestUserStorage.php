<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\Tests;

use Nette\Security\IIdentity;
use Nette\Security\UserStorage;

/** Cookie uloziste, do ktereho se v testech throttlingu nic nezapisuje. */
final class TestUserStorage implements UserStorage
{
	public function saveAuthentication(IIdentity $identity): void
	{
	}

	public function clearAuthentication(bool $clearIdentity): void
	{
	}

	public function getState(): array
	{
		return [false, null, null];
	}

	public function setExpiration(?string $expire, bool $clearIdentity): void
	{
	}
}
