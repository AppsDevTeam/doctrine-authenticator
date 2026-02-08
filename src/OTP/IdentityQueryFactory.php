<?php
declare(strict_types=1);

namespace ADT\DoctrineAuthenticator\OTP;

interface IdentityQueryFactory
{
	public function create(): IdentityQuery;
}