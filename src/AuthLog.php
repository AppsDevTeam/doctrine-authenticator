<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator;

use DateTimeImmutable;
use Doctrine\ORM\Mapping\Column;
use Doctrine\ORM\Mapping\Entity;
use Doctrine\ORM\Mapping\GeneratedValue;
use Doctrine\ORM\Mapping\Id;
use Doctrine\ORM\Mapping\Table;

/**
 * Provozní přehled autentizačních událostí (zapíná se přes
 * DoctrineAuthenticator::setAuthLog(true)).
 *
 * K čemu to je: "kdo se kdy odkud přihlásil" pro podporu a diagnostiku, dostupné
 * přímo z administrace projektu. NENÍ to auditní stopa - ta má být mimo aplikaci,
 * aby ji nemohl přepsat nikdo, kdo se do aplikace dostane. Projekt, který obojí
 * potřebuje, si auditní záznam udělá vedle přes $onAuthEvent; obě kopie jsou pak
 * záměrné a liší se retencí i tím, kdo je smí číst.
 *
 * Entita popisuje schéma pro migrace. Řádky se zapisují přes DBAL (viz
 * DoctrineAuthenticator::dispatchAuthEvent()), nikdy přes ORM, a neaktualizují se.
 * Tabulka roste, dokud ji někdo nemaže - retenci si řídí projekt.
 */
#[Entity]
#[Table(name: "auth_log")]
class AuthLog
{
	#[Id]
	#[Column(type: 'bigint')]
	#[GeneratedValue]
	protected ?string $id = null;

	#[Column(length: 30)]
	protected string $type;

	/** Prihlasovaci jmeno tak, jak ho uzivatel zadal - ucet toho jmena nemusi existovat */
	#[Column(length: DoctrineAuthenticator::IDENTITY_MAX_LENGTH, nullable: true)]
	protected ?string $identity = null;

	#[Column(nullable: true)]
	protected ?string $objectClass = null;

	#[Column(nullable: true)]
	protected ?string $objectId = null;

	/** id session - podle nej se spoji prihlaseni, odhlaseni i zabiti teze session */
	#[Column(nullable: true)]
	protected ?int $storageEntityId = null;

	#[Column(nullable: true)]
	protected ?string $context = null;

	#[Column(length: 45, nullable: true)]
	protected ?string $ip = null;

	// delka drzi konstantu, podle ktere se hodnota zkracuje - jinak by se rozesly
	#[Column(length: DoctrineAuthenticator::USER_AGENT_MAX_LENGTH, nullable: true)]
	protected ?string $userAgent = null;

	/** Proc se to stalo - u selhani trida vyjimky */
	#[Column(length: DoctrineAuthenticator::REASON_MAX_LENGTH, nullable: true)]
	protected ?string $reason = null;

	#[Column(type: 'json', nullable: true)]
	protected ?array $metadata = null;

	/** VZDY V UTC, aby sel zaznam korelovat s ostatnimi logy */
	#[Column]
	protected DateTimeImmutable $createdAt;

	public function getId(): ?string
	{
		return $this->id;
	}

	public function getType(): string
	{
		return $this->type;
	}

	public function getIdentity(): ?string
	{
		return $this->identity;
	}

	public function getObjectClass(): ?string
	{
		return $this->objectClass;
	}

	public function getObjectId(): ?string
	{
		return $this->objectId;
	}

	public function getStorageEntityId(): ?int
	{
		return $this->storageEntityId;
	}

	public function getContext(): ?string
	{
		return $this->context;
	}

	public function getIp(): ?string
	{
		return $this->ip;
	}

	public function getUserAgent(): ?string
	{
		return $this->userAgent;
	}

	public function getReason(): ?string
	{
		return $this->reason;
	}

	public function getMetadata(): ?array
	{
		return $this->metadata;
	}

	public function getCreatedAt(): DateTimeImmutable
	{
		return $this->createdAt;
	}
}
