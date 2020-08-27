<?php

declare(strict_types=1);

namespace Rootshell\Cvss\Calculators;

use Rootshell\Cvss\ValueObjects\CvssObject;

abstract class AbstractCvss3Calculator
{
    abstract public function calculateModifiedImpactSubScore(CvssObject $cvssObject): float;
    abstract public function calculateModifiedImpact(CvssObject $cvssObject): float;
    abstract public function roundUp(float $number): float;

    public function calculateBaseScore(CvssObject $cvssObject): float
    {
        $cvssObject->impactSubScore = $this->calculateImpactSubScore($cvssObject);
        $cvssObject->impact = $this->calculateImpact($cvssObject);
        $cvssObject->exploitability = $this->calculateExploitability($cvssObject);

        if ($cvssObject->impact <= 0) {
            return 0;
        }

        if ($cvssObject->scope === CvssObject::SCOPE_UNCHANGED) {
            return $this->roundUp(min($cvssObject->impact + $cvssObject->exploitability, 10));
        }

        return $this->roundUp(min(1.08 * ($cvssObject->impact + $cvssObject->exploitability), 10));
    }

    public function calculateImpactSubScore(CvssObject $cvssObject): float
    {
        return 1 - ((1 - $cvssObject->confidentiality) * (1 - $cvssObject->integrity) * (1 - $cvssObject->availability));
    }

    public function calculateImpact(CvssObject $cvssObject): float
    {
        if ($cvssObject->scope === CvssObject::SCOPE_UNCHANGED) {
            return 6.42 * $cvssObject->impactSubScore;
        }

        return 7.52 * ($cvssObject->impactSubScore - 0.029) - 3.25 * (($cvssObject->impactSubScore - 0.02) ** 15);
    }

    public function calculateExploitability(CvssObject $cvssObject): float
    {
        return 8.22 * $cvssObject->attackVector * $cvssObject->attackComplexity * $cvssObject->privilegesRequired * $cvssObject->userInteraction;
    }

    public function calculateTemporalScore(CvssObject $cvssObject): float
    {
        return $this->roundUp($cvssObject->baseScore * $cvssObject->exploitCodeMaturity * $cvssObject->remediationLevel * $cvssObject->reportConfidence);
    }

    public function calculateModifiedExploitability(CvssObject $cvssObject): float
    {
        return 8.22 * $cvssObject->modifiedAttackVector * $cvssObject->modifiedAttackComplexity * $cvssObject->modifiedPrivilegesRequired * $cvssObject->modifiedUserInteraction;
    }

    public function calculateEnvironmentalScore(CvssObject $cvssObject): float
    {
        $cvssObject->modifiedImpactSubScore = $this->calculateModifiedImpactSubScore($cvssObject);
        $cvssObject->modifiedImpact = $this->calculateModifiedImpact($cvssObject);
        $cvssObject->modifiedExploitability = $this->calculateModifiedExploitability($cvssObject);

        if ($cvssObject->modifiedImpact <= 0) {
            return 0;
        }

        if ($cvssObject->modifiedScope === CvssObject::SCOPE_UNCHANGED) {
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
