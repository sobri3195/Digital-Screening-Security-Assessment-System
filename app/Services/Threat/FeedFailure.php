<?php
declare(strict_types=1);
namespace Sentinel\Services\Threat;

final class FeedFailure extends \RuntimeException
{
    public function __construct(string $message, public readonly bool $retry = false, public readonly int $delay = 0)
    {
        parent::__construct($message);
    }
}
