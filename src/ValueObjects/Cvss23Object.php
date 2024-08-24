<?php

declare(strict_types=1);

namespace Rootshell\CVSS\ValueObjects;

class CVSS23Object extends CVSSObject
{
    public const SCOPE_UNCHANGED = 'U';
    public const SCOPE_CHANGED = 'C';

    public string $version = self::VERSION_31;

    public string $scope = self::SCOPE_UNCHANGED;

    public string $modifiedScope = self::SCOPE_UNCHANGED;

    public float $attackVector = 0.0;

    public float $accessVector = 0.0;

    public float $attackComplexity = 0.0;

    public float $accessComplexity = 0.0;

    public float $authentication = 0.0;

    public float $privilegesRequired = 0.0;

    public float $userInteraction = 0.0;

    public float $confidentiality = 0.0;

    public float $integrity = 0.0;

    public float $availability = 0.0;

    public float $impact = 0.0;

    public float $exploitability = 0.0;

    public float $impactSubScore = 0.0;

    public float $exploitCodeMaturity = 0.0;

    public float $remediationLevel = 0.0;

    public float $reportConfidence = 0.0;

    public float $confidentialityRequirement = 0.0;

    public float $integrityRequirement = 0.0;

    public float $availabilityRequirement = 0.0;

    public float $modifiedAttackVector = 0.0;

    public float $modifiedAttackComplexity = 0.0;

    public float $modifiedPrivilegesRequired = 0.0;

    public float $modifiedUserInteraction = 0.0;

    public float $modifiedConfidentiality = 0.0;

    public float $modifiedIntegrity = 0.0;

    public float $modifiedAvailability = 0.0;

    public float $modifiedImpactSubScore = 0.0;

    public float $modifiedImpact = 0.0;

    public float $modifiedExploitability = 0.0;

    public float $collateralDamagePotential = 0.0;

    public float $targetDistribution = 0.0;
}
