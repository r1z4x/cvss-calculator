<?php

declare(strict_types=1);

namespace Rootshell\CVSS\Calculators;

use http\Exception\RuntimeException;
use Rootshell\CVSS\ValueObjects\CVSS23Object;
use Rootshell\CVSS\ValueObjects\CVSSObject;

abstract class AbstractCVSS3Calculator implements CVSSCalculator
{
    abstract public function calculateModifiedImpactSubScore(CVSSObject $cvssObject): float;
    abstract public function calculateModifiedImpact(CVSSObject $cvssObject): float;
    abstract public function roundUp(float $number): float;

    public function calculateBaseScore(CVSSObject $cvssObject): float
    {
        if (!$cvssObject instanceof CVSS23Object) {
            throw new \RuntimeException('Wrong CVSS object');
        }

        $cvssObject->impactSubScore = $this->calculateImpactSubScore($cvssObject);
        $cvssObject->impact = $this->calculateImpact($cvssObject);
        $cvssObject->exploitability = $this->calculateExploitability($cvssObject);

        if ($cvssObject->impact <= 0) {
            return 0;
        }

        if ($cvssObject->scope === CVSS23Object::SCOPE_UNCHANGED) {
            return $this->roundUp(min($cvssObject->impact + $cvssObject->exploitability, 10));
        }

        return $this->roundUp(min(1.08 * ($cvssObject->impact + $cvssObject->exploitability), 10));
    }

    private function calculateImpactSubScore(CVSS23Object $cvssObject): float
    {
        return 1 - ((1 - $cvssObject->confidentiality) * (1 - $cvssObject->integrity) * (1 - $cvssObject->availability));
    }

    private function calculateImpact(CVSS23Object $cvssObject): float
    {
        if ($cvssObject->scope === CVSS23Object::SCOPE_UNCHANGED) {
            return 6.42 * $cvssObject->impactSubScore;
        }

        return 7.52 * ($cvssObject->impactSubScore - 0.029) - 3.25 * (($cvssObject->impactSubScore - 0.02) ** 15);
    }

    private function calculateExploitability(CVSS23Object $cvssObject): float
    {
        return 8.22 * $cvssObject->attackVector * $cvssObject->attackComplexity * $cvssObject->privilegesRequired * $cvssObject->userInteraction;
    }

    public function calculateTemporalScore(CVSSObject $cvssObject): float
    {
        if (!$cvssObject instanceof CVSS23Object) {
            throw new \RuntimeException('Wrong CVSS object');
        }

        return $this->roundUp($cvssObject->baseScore * $cvssObject->exploitCodeMaturity * $cvssObject->remediationLevel * $cvssObject->reportConfidence);
    }

    private function calculateModifiedExploitability(CVSS23Object $cvssObject): float
    {
        return 8.22 * $cvssObject->modifiedAttackVector * $cvssObject->modifiedAttackComplexity * $cvssObject->modifiedPrivilegesRequired * $cvssObject->modifiedUserInteraction;
    }

    public function calculateEnvironmentalScore(CVSSObject $cvssObject): float
    {
        if (!$cvssObject instanceof CVSS23Object) {
            throw new \RuntimeException('Wrong CVSS object');
        }

        $cvssObject->modifiedImpactSubScore = $this->calculateModifiedImpactSubScore($cvssObject);
        $cvssObject->modifiedImpact = $this->calculateModifiedImpact($cvssObject);
        $cvssObject->modifiedExploitability = $this->calculateModifiedExploitability($cvssObject);

        if ($cvssObject->modifiedImpact <= 0) {
            return 0;
        }

        if ($cvssObject->modifiedScope === CVSS23Object::SCOPE_UNCHANGED) {
            return $this->roundUp(
                $this->roundUp(
                    min($cvssObject->modifiedImpact + $cvssObject->modifiedExploitability, 10)
                ) * $cvssObject->exploitCodeMaturity * $cvssObject->remediationLevel * $cvssObject->reportConfidence
            );
        }

        return $this->roundup(
            $this->roundup(
                min(
                    1.08 * ($cvssObject->modifiedImpact + $cvssObject->modifiedExploitability),
                    10
                )
            ) * $cvssObject->exploitCodeMaturity * $cvssObject->remediationLevel * $cvssObject->reportConfidence
        );
    }
}
