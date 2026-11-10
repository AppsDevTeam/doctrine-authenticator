<?php

declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\Tests;

use ADT\DoctrineAuthenticator\OTP\IdentityQuery;
use ADT\DoctrineAuthenticator\OTP\IdentityQueryFactory;
use ADT\DoctrineAuthenticator\OTP\OnetimeTokenAuthenticator;
use ADT\DoctrineAuthenticator\OTP\OnetimeTokenService;
use ADT\DoctrineAuthenticator\Tests\Entity\TestOtpUser;
use Doctrine\ORM\EntityManagerInterface;
use LogicException;
use Nette\Http\Request;
use Nette\Http\UrlScript;
use Nette\Security\IIdentity;

/** OnetimeTokenAuthenticator, ktery identitu hleda primo v repozitari misto query objektu projektu. */
final class TestOnetimeTokenAuthenticator extends OnetimeTokenAuthenticator
{
	public function __construct(EntityManagerInterface $em)
	{
		parent::__construct(
			'14 days',
			new TestUserStorage(),
			$em,
			new Request(new UrlScript('https://example.com/'), remoteAddress: '127.0.0.1'),
			new OnetimeTokenService($em),
			new class implements IdentityQueryFactory {
				public function create(): IdentityQuery
				{
					throw new LogicException('Identity is looked up in findIdentity().');
				}
			},
		);
	}

	public function findIdentity(string $identifier, ?string $context = null, array $metadata = []): ?IIdentity
	{
		return $this->em->getRepository(TestOtpUser::class)->findOneBy(['email' => $identifier]);
	}
}
