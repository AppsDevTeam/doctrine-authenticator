<?php

namespace ADT\DoctrineAuthenticator;

use Nette\Security\IIdentity;

class FakeIdentity implements IIdentity
{
	private int $id;

	private string $class;

	public function __construct(int $id, string $class)
	{
		$this->id = $id;
		$this->class = $class;
	}

	public function getId(): int
	{
		return $this->id;
	}

	public function getClass(): string
	{
		return $this->class;
	}

	public function getRoles(): array
	{
		return [];
	}
}
