<?php

declare(strict_types=1);

namespace Rootshell\CVSS\Calculators;

use http\Exception\RuntimeException;
use Rootshell\CVSS\ValueObjects\CVSS23Object;
use Rootshell\CVSS\ValueObjects\CVSSObject;

class CVSS30Calculator extends AbstractCVSS3Calculator
{
    public function calculateModifiedImpactSubScore(CVSSObject $cvssObject): float
    {
        if (!$cvssObject instanceof CVSS23Object) {
            throw new \RuntimeException('Wrong CVSS object');
        }

        return min(
            1 - ((1 - $cvssObject->confidentialityRequirement * $cvssObject->modifiedConfidentiality) *
                (1 - $cvssObject->integrityRequirement * $cvssObject->modifiedIntegrity) *
                (1 - $cvssObject->availabilityRequirement * $cvssObject->modifiedAvailability)),
            0.915
        );
    }

    public function calculateModifiedImpact(CVSSObject $cvssObject): float
    {
        if (!$cvssObject instanceof CVSS23Object) {
            throw new \RuntimeException('Wrong CVSS object');
        }

        if ($cvssObject->modifiedScope === CVSS23Object::SCOPE_UNCHANGED) {
            return 6.42 * $cvssObject->modifiedImpactSubScore;
        }

        return 7.52 * ($cvssObject->modifiedImpactSubScore - 0.029) - 3.25 * (($cvssObject->modifiedImpactSubScore - 0.02) ** 15);
    }

    public function roundUp(float $number): float
    {
        return round(ceil($number * 10) / 10, 1);
    }

    public function calculateSeverity(CVSSObject $cvssObject): string
    {
        $baseScore = $this->calculateBaseScore($cvssObject);

        return match (true) {
            $baseScore >= 9.0 => 'C',
            $baseScore >= 7.0 => 'H',
            $baseScore >= 4.0 => 'M',
            $baseScore >= 0.1 => 'L',
            $baseScore === 0.0 => 'N',
            default => 'N/A',
        };
    }
}
