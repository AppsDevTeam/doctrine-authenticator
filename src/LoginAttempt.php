<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator;

use DateTimeImmutable;
use Doctrine\ORM\Mapping\Column;
use Doctrine\ORM\Mapping\Entity;
use Doctrine\ORM\Mapping\GeneratedValue;
use Doctrine\ORM\Mapping\Id;
use Doctrine\ORM\Mapping\Index;
use Doctrine\ORM\Mapping\Table;

#[Entity]
#[Index(fields: ["ipAddress", "createdAt"])]
class LoginAttempt
{
	#[Id]
	#[Column]
	#[GeneratedValue]
	protected ?int $id = null;

	#[Column(length: 45)]
	protected string $ipAddress;

	#[Column]
	protected DateTimeImmutable $createdAt;

	public function __construct(string $ipAddress)
	{
		$this->ipAddress = $ipAddress;
		$this->createdAt = new DateTimeImmutable();
	}
}
