<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator;

use DateTimeImmutable;

/**
 * What the throttling currently thinks of one login name, see
 * {@see DoctrineAuthenticator::getLoginThrottleStatus()}.
 *
 * It exists so a sign-in form can say "two attempts left" and "try again at 14:32" instead
 * of the same "invalid credentials" it showed on the first typo. Without it the counters are
 * invisible from the outside: a locked-out user cannot tell that anything changed, let alone
 * when it ends, and goes to support instead.
 */
readonly class LoginThrottleStatus
{
	public function __construct(
		/** Failed attempts left before sign-in is refused; null when throttling is off */
		public ?int $remainingAttempts,
		/** When sign-in becomes possible again; null when it is not being refused */
		public ?DateTimeImmutable $blockedUntil,
	) {
	}

	public function isBlocked(): bool
	{
		return $this->blockedUntil !== null;
	}
}
