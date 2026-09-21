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
		/** Is sign-in being refused right now? */
		public bool $blocked,
		/**
		 * When sign-in becomes possible again - null even while blocked, if the moment could
		 * not be determined. Deliberately separate from $blocked: whether to refuse must never
		 * depend on whether we can also name the time, or a hiccup in that second question
		 * would open the door.
		 */
		public ?DateTimeImmutable $blockedUntil,
	) {
	}

	public function isBlocked(): bool
	{
		return $this->blocked;
	}
}
