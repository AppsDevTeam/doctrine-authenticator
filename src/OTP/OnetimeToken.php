<?php
declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

use ADT\DoctrineComponents\Entities\Entity;
use DateTimeImmutable;

interface OnetimeToken extends Entity
{
	/*
	 * Konstanty pro nastaveni jak dlouho je validni request pro obnovu hesla a jak dlouho je validni request v pripade
	 * vytvareni novehe uzivatele
	 */
	const int PASSWORD_RECOVERY_VALID_FOR = 24; //hour
	const int PASSWORD_CREATION_VALID_FOR = 72; //hours (3 days)

	public function getToken(): string;
	public function setToken(string $token): static;
	public function getObjectId(): ?int;
	public function setObjectId(?int $objectId): static;
	public function getUsedAt(): ?DateTimeImmutable;
	public function setUsedAt(?DateTimeImmutable $usedAt): static;
	public function setValidUntil(DateTimeImmutable $validUntil): static;
	public function getValidUntil(): DateTimeImmutable;
	public function getType(): string;
	public function setType(string $type): static;
	public function getIpAddress(): string;
	public function setIpAddress(string $ipAddress): static;
	public function getObjectClass(): ?string;
	public function setObjectClass(?string $objectClass): static;
	public function getIdentifier(): ?string;
	public function setIdentifier(?string $identifier): static;

	public function isValid(): bool;
}
