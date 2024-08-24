<?php

namespace Rootshell\CVSS\ValueObjects;

class CVSSObject
{
    public const VERSION_2 = '2';
    public const VERSION_31 = '3.1';
    public const VERSION_30 = '3.0';
    public const VERSION_40 = '4.0';

    public float $baseScore = 0.0;
    public float $temporalScore = 0.0;
    public float $environmentalScore = 0.0;
    public string $severity = 'N/A';

    public function getResults(): CVSSResults
    {
        return new CVSSResults($this->baseScore, $this->temporalScore, $this->environmentalScore, $this->severity);
    }
}
