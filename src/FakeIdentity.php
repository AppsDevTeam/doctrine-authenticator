<?php

namespace ADT\DoctrineAuthenticator;

use Nette\Security\IIdentity;

class FakeIdentity implements IIdentity
{
	/** @var array<string, mixed> */
	private array $id;

	private string $class;

	/**
	 * @param array<string, mixed> $id
	 */
	public function __construct(array $id, string $class)
	{
		$this->id = $id;
		$this->class = $class;
	}

	/**
	 * @return array<string, mixed>
	 */
	public function getId(): array
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
