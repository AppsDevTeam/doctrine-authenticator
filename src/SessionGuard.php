<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator;

use Nette\Http\Session;
use Nette\Security\User;

/**
 * Ties the PHP session to the account that owns it.
 *
 * With CookieStorage the authentication lives in its own cookie, so the PHP session is
 * never consulted to decide who the visitor is - and consequently Nette never rotates it
 * on sign-in the way its session-backed storage does. The session id therefore survives
 * signing in, signing out and signing in as somebody else, which is CWE-384: anyone who
 * can fix a visitor's session id keeps reading and writing that session after the visitor
 * authenticates.
 *
 * Two rules, both needed:
 *
 *  - the id is rotated on every sign-in and the session is dropped on sign-out, so an id
 *    known before authentication is worthless afterwards;
 *  - the session records whose it is, and a session that turns up under a different
 *    account is discarded rather than adopted. The rotation alone only covers the paths
 *    that go through login()/logout(); the binding also covers the authentication cookie
 *    changing underneath an existing session.
 *
 * Wire the first two onto the security user and call enforceBinding() early in the
 * request (a base presenter's startup()):
 *
 *   security.user:
 *       setup:
 *           - '$onLoggedIn[]' = [@ADT\DoctrineAuthenticator\SessionGuard, bindToIdentity]
 *           - '$onLoggedOut[]' = [@ADT\DoctrineAuthenticator\SessionGuard, releaseIdentity]
 *
 * Register it only where the session actually is - wiring it into an API module that
 * signs in per request would hand out session cookies to clients that never use them.
 */
class SessionGuard
{
	private const string SECTION = 'adt.sessionGuard';
	private const string KEY = 'identity';

	public function __construct(private readonly Session $session)
	{
	}

	/**
	 * A fresh id for the authenticated session, stamped with its owner.
	 *
	 * Runs after the authentication cookie is written, so by now there is an identity to
	 * stamp it with. Nette rotates at most once per request, which is what we want: on
	 * a straight account switch login() signs the previous identity out first, and both
	 * hooks fire within the one request.
	 */
	public function bindToIdentity(User $user): void
	{
		$this->session->regenerateId();
		$this->session->getSection(self::SECTION)->set(self::KEY, $this->identityOf($user));
	}

	/**
	 * Signing out drops the session rather than just unbinding it - flash messages, grid
	 * filters and half-filled forms are the previous account's, and whoever signs in on
	 * this browser next has no business inheriting them.
	 */
	public function releaseIdentity(): void
	{
		$this->discard();
	}

	/**
	 * A session whose owner no longer matches the authenticated account is somebody
	 * else's and gets thrown away.
	 *
	 * Deliberately silent when no session is in play: reading the section would start one,
	 * and that would mean a session cookie for every anonymous visitor and crawler.
	 * An unstamped session is stamped rather than discarded - it is the ordinary case of
	 * a session that outlived its data, not evidence of anything.
	 */
	public function enforceBinding(User $user): void
	{
		if (!$this->session->exists()) {
			return;
		}

		$identity = $this->identityOf($user);
		$owner = $this->session->getSection(self::SECTION)->get(self::KEY);

		if ($owner === $identity) {
			return;
		}

		if ($owner !== null) {
			$this->discard();
		}

		if ($identity !== null) {
			$this->session->getSection(self::SECTION)->set(self::KEY, $identity);
		}
	}

	private function discard(): void
	{
		if ($this->session->isStarted()) {
			$this->session->destroy();
		}

		// session_destroy() leaves the id in place, so a session started later in this
		// request would come back under the id we just threw away.
		$this->session->regenerateId();
	}

	private function identityOf(User $user): ?string
	{
		return $user->isLoggedIn() ? (string) $user->getId() : null;
	}
}
