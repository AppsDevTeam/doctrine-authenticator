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
use Throwable;

#[Entity]
#[Index(fields: ["ipAddress", "createdAt"])]
#[Index(fields: ["username", "createdAt"])]
class LoginAttempt
{
	private const USERNAME_MAX_LENGTH = 255;
	private const EXCEPTION_MAX_LENGTH = 255;
	private const EXCEPTION_MESSAGE_MAX_LENGTH = 5000;

	#[Id]
	#[Column]
	#[GeneratedValue]
	protected ?int $id = null;

	#[Column(length: 45)]
	protected string $ipAddress;

	#[Column(nullable: true)]
	protected ?string $username = null;

	#[Column(nullable: true)]
	protected ?string $exception = null;

	#[Column(type: 'text', nullable: true)]
	protected ?string $exceptionMessage = null;

	#[Column]
	protected DateTimeImmutable $createdAt;

	public function __construct(string $ipAddress, ?string $username = null, ?Throwable $exception = null)
	{
		$this->ipAddress = $ipAddress;
		$this->createdAt = new DateTimeImmutable();

		// An attacker controls the username, so never let its length break the insert.
		if ($username !== null) {
			$this->username = mb_substr($username, 0, self::USERNAME_MAX_LENGTH);
		}

		if ($exception !== null) {
			$this->exception = mb_substr($exception::class, 0, self::EXCEPTION_MAX_LENGTH);
			$this->exceptionMessage = $exception->getMessage() !== ''
				? mb_substr($exception->getMessage(), 0, self::EXCEPTION_MESSAGE_MAX_LENGTH)
				: null;
		}
	}

	public function getId(): ?int
	{
		return $this->id;
	}

	public function getIpAddress(): string
	{
		return $this->ipAddress;
	}

	public function getUsername(): ?string
	{
		return $this->username;
	}

	public function getException(): ?string
	{
		return $this->exception;
	}

	public function getExceptionMessage(): ?string
	{
		return $this->exceptionMessage;
	}

	public function getCreatedAt(): DateTimeImmutable
	{
		return $this->createdAt;
	}
}
