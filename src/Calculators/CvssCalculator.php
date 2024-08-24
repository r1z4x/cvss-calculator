<?php

namespace Rootshell\CVSS\Calculators;

use Rootshell\CVSS\ValueObjects\CVSSObject;

interface CVSSCalculator
{
    public function calculateBaseScore(CVSSObject $cvssObject): float;
    public function calculateTemporalScore(CVSSObject $cvssObject): float;
    public function calculateEnvironmentalScore(CVSSObject $cvssObject): float;
    public function calculateSeverity(CVSSObject $cvssObject): string;
}
