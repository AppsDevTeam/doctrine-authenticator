<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator;

use Nette;
use Nette\Http;
use Nette\Security\IIdentity;


/**
 * Cookie storage for Nette\Security\User object.
 */
final class CookieStorage implements Nette\Security\UserStorage
{
	use Nette\SmartObject;

	private const MIN_LENGTH = 13;

	/** @var Http\IRequest */
	private $request;

	/** @var Http\IResponse */
	private $response;

	/** @var ?string */
	private $uid;

	/** @var string */
	private $cookieName = 'userid';

	/** @var ?string */
	private $cookieDomain;

	/** @var string */
	private $cookieSameSite = 'Lax';

	/** @var ?string */
	private $cookieExpiration;


	public function __construct(Http\IRequest $request, Http\IResponse $response)
	{
		$this->response = $response;
		$this->request = $request;
	}


	public function saveAuthentication(IIdentity $identity): void
	{
		$uid = (string) $identity->getId();
		if (strlen($uid) < self::MIN_LENGTH) {
			throw new \LogicException('UID is too short.');
		}

		$this->uid = $uid;
		$this->setCookie($uid);
	}


	public function clearAuthentication(bool $clearIdentity): void
	{
		$this->uid = '';
		$this->response->deleteCookie(
			$this->cookieName,
			null,
			$this->cookieDomain
		);
	}


	public function getState(): array
	{
		if ($this->uid === null) {
			$uid = $this->request->getCookie($this->cookieName);
			$this->uid = is_string($uid) && strlen($uid) >= self::MIN_LENGTH ? $uid : '';
		}

		return $this->uid
			? [true, new Nette\Security\SimpleIdentity($this->uid), null]
			: [false, null, null];
	}


	public function setExpiration(?string $expire, bool $clearIdentity): void
	{
		$this->cookieExpiration = $expire;
		if ($this->uid) {
			$this->setCookie($this->uid);
		}
	}


	public function setCookieParameters(
		?string $name = null,
		?string $domain = null,
		?string $sameSite = null
	) {
		$this->cookieName = $name ?? $this->cookieName;
		$this->cookieDomain = $domain ?? $this->cookieDomain;
		$this->cookieSameSite = $sameSite ?? $this->cookieSameSite;
	}


	private function setCookie(string $uid): void
	{
		$this->response->setCookie(
			$this->cookieName,
			$uid,
			$this->cookieExpiration,
			null,
			$this->cookieDomain,
			null,
			true,
			$this->cookieSameSite
		);
	}
}
