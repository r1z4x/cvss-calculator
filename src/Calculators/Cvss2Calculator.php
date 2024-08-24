<?php

namespace Rootshell\CVSS\Calculators;

use Rootshell\CVSS\CVSS;
use Rootshell\CVSS\ValueObjects\CVSS23Object;
use Rootshell\CVSS\ValueObjects\CVSSObject;

class CVSS2Calculator implements CVSSCalculator
{
    public function calculateBaseScore(CVSSObject $cvssObject): float
    {
        if (!$cvssObject instanceof CVSS23Object) {
            throw new \RuntimeException('Wrong CVSS object');
        }

        $cvssObject->impact = $this->calculateImpact($cvssObject);

        return round(((0.6 * $cvssObject->impact) + (0.4 * $this->calculateBaseExploitability($cvssObject)) - 1.5) * $this->calculateFImpact($cvssObject), 1);
    }

    private function calculateImpact(CVSS23Object $cvssObject): float
    {
        return 10.41 * (1 - (1 - $cvssObject->confidentiality) * (1 - $cvssObject->integrity) * (1 - $cvssObject->availability));
    }

    private function calculateBaseExploitability(CVSS23Object $cvssObject): float
    {
        return 20 * $cvssObject->accessVector * $cvssObject->accessComplexity * $cvssObject->authentication;
    }

    private function calculateFImpact(CVSS23Object $cvssObject): float
    {
        return $cvssObject->impact === 0.0 ? 0.0 : 1.176;
    }

    public function calculateTemporalScore(CVSSObject $cvssObject): float
    {
        if (!$cvssObject instanceof CVSS23Object) {
            throw new \RuntimeException('Wrong CVSS object');
        }

        return round($cvssObject->baseScore * $cvssObject->exploitability * $cvssObject->remediationLevel * $cvssObject->reportConfidence, 1);
    }

    public function calculateEnvironmentalScore(CVSSObject $cvssObject): float
    {
        if (!$cvssObject instanceof CVSS23Object) {
            throw new \RuntimeException('Wrong CVSS object');
        }

        $adjustedTemporal = $this->calculateAdjustedTemporal($cvssObject);

        return round(($adjustedTemporal + (10 - $adjustedTemporal) * $cvssObject->collateralDamagePotential) * $cvssObject->targetDistribution, 1);
    }

    private function calculateAdjustedTemporal(CVSS23Object $cvssObject): float
    {
        return $this->calculateAdjustedBase($cvssObject) * $cvssObject->exploitability * $cvssObject->remediationLevel * $cvssObject->reportConfidence;
    }

    private function calculateAdjustedBase(CVSS23Object $cvssObject): float
    {
        return round(((0.6 * $this->calculateAdjustedImpact($cvssObject)) + (0.4 * $this->calculateBaseExploitability($cvssObject)) - 1.5) * $this->calculateFImpact($cvssObject), 1);
    }

    private function calculateAdjustedImpact(CVSS23Object $cvssObject): float
    {
        return min(10, 10.41 * (1 - (1 - $cvssObject->confidentiality * $cvssObject->confidentialityRequirement) * (1 - $cvssObject->integrity * $cvssObject->integrityRequirement) * (1 - $cvssObject->availability * $cvssObject->availabilityRequirement)));
    }

    public function calculateSeverity(CVSSObject $cvssObject): string
    {
        $baseScore = $this->calculateBaseScore($cvssObject);

        return match (true) {
            $baseScore >= 7.0 => 'H',
            $baseScore >= 4.0 => 'M',
            $baseScore >= 0.0 => 'L',
            default => 'N/A',
        };
    }
}
