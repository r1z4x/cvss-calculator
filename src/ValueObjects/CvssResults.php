<?php

namespace Rootshell\CVSS\ValueObjects;

class CVSSResults
{
    public function __construct(
        public float $baseScore,
        public float $temporalScore,
        public float $environmentalScore,
        public string $severity
    ) {
    }
}
