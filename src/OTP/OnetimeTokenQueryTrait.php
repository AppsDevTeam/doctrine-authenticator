<?php
declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

use Doctrine\ORM\QueryBuilder;

trait OnetimeTokenQueryTrait
{
	public function byToken(string $token): static
	{
		return $this->by('token', $token);
	}

	public function byType(string $type): static
	{
		return $this->by('type', $type);
	}

	public function byIdentifier(?string $identifier): static
	{
		return $this->by('identifier', $identifier);
	}

	public function byIsValid(bool $checkValidUntil = true): static
	{
		if ($checkValidUntil) {
			$this->filter[] = function (QueryBuilder $qb) {
				$qb->andWhere('e.validUntil >= :now')
					->andWhere('e.usedAt IS NULL')
					->setParameter('now', new \DateTimeImmutable());
			};
			return $this;
		}

		return $this->by('usedAt', null);
	}
}