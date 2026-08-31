<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator;

use DateTimeImmutable;

/**
 * Zapisovac auditni stopy autentizacnich udalosti. Implementaci dodava
 * aplikace nebo nadrazeny balicek (typicky adt/fancyadmin, ktery vlastni
 * jednotnou tabulku audit_log) - knihovna tak nemusi mit vlastni entitu
 * ani vedet, kam se audit uklada.
 *
 * Rozhrani je zamerne jen ze SKALARU A POLI: implementace nemusi znat typy
 * teto knihovny, takze na ni nemusi zaviset.
 *
 * Neni-li zaregistrovana zadna implementace, autentizacni audit se nepise
 * (viz DoctrineAuthenticator::setAuthLog()). Na rozdil od exportu tu tichy
 * no-op smysl ma: prihlaseni nesmi selhat proto, ze nejde zapsat log.
 */
interface AuthAuditLogger
{
	public const string ACTION_LOGIN = 'login';
	public const string ACTION_LOGIN_FAILED = 'login_failed';
	public const string ACTION_LOGIN_BLOCKED = 'login_blocked';
	public const string ACTION_LOGOUT = 'logout';
	public const string ACTION_INVALID_TOKEN = 'invalid_token';

	/**
	 * Zapise auditni udalost.
	 *
	 * @param string $action ACTION_* konstanta
	 * @param DateTimeImmutable $createdAt v UTC
	 * @param string|null $correlationId spojuje udalosti tehoz prihlaseni
	 *        (id session storage), takze je dohledatelny cely jeji pribeh
	 * @param array{id: string|null, label: string|null, data: array, ip: string|null, userAgent: string|null} $actor
	 * @param array $payload obsah dle akce - napr. duvod zamitnuti, kontext,
	 *        trida a id dotcene entity
	 * @param bool $detached TRUE = zapsat vlastnim spojenim MIMO probihajici
	 *        transakci. Autentizace to potrebuje: zaznam o neuspesnem pokusu
	 *        musi prezit rollback transakce, ktera pokus zamitla.
	 */
	public function log(
		string $action,
		DateTimeImmutable $createdAt,
		?string $correlationId,
		array $actor,
		array $payload,
		bool $detached = false,
	): void;
}
