<?php

namespace Rootshell\CVSS\Parsers;

use Rootshell\CVSS\Exceptions\CVSSException;
use Rootshell\CVSS\ValueObjects\CVSS23Object;

class CVSS2Parser
{
    private const NETWORK = 'N';
    private const ADJACENT = 'A';
    private const LOCAL = 'L';

    private const LOW = 'L';
    private const MEDIUM = 'M';
    private const HIGH = 'H';

    private const MULTIPLE = 'M';
    private const SINGLE = 'S';
    private const NONE = 'N';

    private const PARTIAL = 'P';
    private const COMPLETE = 'C';

    private const UNPROVEN = 'U';
    private const PROOF_OF_CONCEPT = 'POC';
    private const FUNCTIONAL = 'F';
    private const NOT_DEFINED = 'ND';

    private const OFFICIAL_FIX = 'OF';
    private const TEMPORARY_FIX = 'TF';
    private const WORKAROUND = 'W';
    private const UNAVAILABLE = 'U';

    private const UNCONFIRMED = 'UC';
    private const UNCORROBORATED = 'UR';
    private const CONFIRMED = 'C';

    private const LOW_MEDIUM = 'LM';
    private const MEDIUM_HIGH = 'MH';

    private const BASE_ACCESS_VECTOR = 'AV';
    private const BASE_ATTACK_COMPLEXITY = 'AC';
    private const BASE_AUTHENTICATION = 'Au';
    private const BASE_CONFIDENTIALITY = 'C';
    private const BASE_INTEGRITY = 'I';
    private const BASE_AVAILABILITY = 'A';

    private const TEMPORAL_EXPLOITABILITY = 'E';
    private const TEMPORAL_REMEDIATION_LEVEL = 'RL';
    private const TEMPORAL_REPORT_CONFIDENCE = 'RC';

    private const ENVIRONMENTAL_COLLATERAL_DAMAGE_POTENTIAL  = 'CDP';
    private const ENVIRONMENTAL_TARGET_DISTRIBUTION = 'TD';
    private const ENVIRONMENTAL_CONFIDENTIALITY_REQUIREMENT = 'CR';
    private const ENVIRONMENTAL_INTEGRITY_REQUIREMENT = 'IR';
    private const ENVIRONMENTAL_AVAILABILITY_REQUIREMENT = 'AR';


    public static function parseVector(string $vector): CVSS23Object
    {
        $cvssObject = new CVSS23Object();
        $cvssObject = self::parseBaseValues($vector, $cvssObject);
        $cvssObject = self::parseTemporalValues($vector, $cvssObject);
        $cvssObject = self::parseEnvironmentalValues($vector, $cvssObject);

        return $cvssObject;
    }

    private static function parseBaseValues(string $vector, CVSS23Object $cvssObject): CVSS23Object
    {
        $cvssObject->accessVector = self::parseAccessVector(self::findValueInVector($vector, self::BASE_ACCESS_VECTOR));
        $cvssObject->accessComplexity = self::parseAccessComplexity(self::findValueInVector($vector, self::BASE_ATTACK_COMPLEXITY));
        $cvssObject->authentication = self::parseAuthentication(self::findValueInVector($vector, self::BASE_AUTHENTICATION));
        $cvssObject->confidentiality = self::parseConfidentialityIntegrityAvailabilityImpact(self::findValueInVector($vector, self::BASE_CONFIDENTIALITY));
        $cvssObject->integrity = self::parseConfidentialityIntegrityAvailabilityImpact(self::findValueInVector($vector, self::BASE_INTEGRITY));
        $cvssObject->availability = self::parseConfidentialityIntegrityAvailabilityImpact(self::findValueInVector($vector, self::BASE_AVAILABILITY));
        return $cvssObject;
    }

    private static function parseTemporalValues(string $vector, CVSS23Object $cvssObject): CVSS23Object
    {
        $cvssObject->exploitability = self::parseExploitability(self::findOptionalValueInVector($vector, self::TEMPORAL_EXPLOITABILITY));
        $cvssObject->remediationLevel = self::parseRemediationLevel(self::findOptionalValueInVector($vector, self::TEMPORAL_REMEDIATION_LEVEL));
        $cvssObject->reportConfidence = self::parseReportConfidence(self::findOptionalValueInVector($vector, self::TEMPORAL_REPORT_CONFIDENCE));

        return $cvssObject;
    }

    private static function parseEnvironmentalValues(string $vector, CVSS23Object $cvssObject): CVSS23Object
    {
        $cvssObject->collateralDamagePotential = self::parseCollateralDamagePotential(self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_COLLATERAL_DAMAGE_POTENTIAL));
        $cvssObject->targetDistribution = self::parseTargetDistribution(self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_TARGET_DISTRIBUTION));
        $cvssObject->confidentialityRequirement = self::parseSecurityRequirements(self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_CONFIDENTIALITY_REQUIREMENT));
        $cvssObject->integrityRequirement = self::parseSecurityRequirements(self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_INTEGRITY_REQUIREMENT));
        $cvssObject->availabilityRequirement = self::parseSecurityRequirements(self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_AVAILABILITY_REQUIREMENT));

        return $cvssObject;
    }


    private static function findValueInVector(string $vector, string $section): string
    {
        $regex = '/(?<=\/' . $section . ':)(.*?)(?=\/|$)/';
        preg_match($regex, '/' . $vector, $matches);

        if (!isset($matches[0])) {
            throw CVSSException::missingValue();
        }

        return $matches[0];
    }

    private static function findOptionalValueInVector(string $vector, string $section): ?string
    {
        $regex = '/(?<=\/' . $section . ':)(.*?)(?=\/|$)/';
        preg_match($regex, '/' . $vector, $matches);

        return $matches[0] ?? null;
    }

    private static function parseAccessVector(string $value): float
    {
        return match ($value) {
            self::NETWORK => 1,
            self::ADJACENT => 0.646,
            self::LOCAL => 0.395,
            default => throw CVSSException::invalidValue(),
        };
    }

    private static function parseAccessComplexity(string $value): float
    {
        return match ($value) {
            self::HIGH => 0.35,
            self::MEDIUM => 0.61,
            self::LOW => 0.71,
            default => throw CVSSException::invalidValue(),
        };
    }

    private static function parseAuthentication(string $value): float
    {
        return match ($value) {
            self::MULTIPLE => 0.45,
            self::SINGLE => 0.56,
            self::NONE => 0.704,
            default => throw CVSSException::invalidValue(),
        };
    }

    private static function parseConfidentialityIntegrityAvailabilityImpact(string $value): float
    {
        return match ($value) {
            self::COMPLETE => 0.660,
            self::PARTIAL => 0.275,
            self::NONE => 0.0,
            default => throw CVSSException::invalidValue(),
        };
    }

    private static function parseExploitability(?string $value): float
    {
        return match ($value) {
            self::UNPROVEN => 0.85,
            self::PROOF_OF_CONCEPT => 0.9,
            self::FUNCTIONAL => 0.95,
            default => 1.0,
        };
    }

    private static function parseRemediationLevel(?string $value): float
    {
        return match ($value) {
            self::OFFICIAL_FIX => 0.87,
            self::TEMPORARY_FIX => 0.90,
            self::WORKAROUND => 0.95,
            default => 1.0,
        };
    }

    private static function parseReportConfidence(?string $value): float
    {
        return match ($value) {
            self::UNCONFIRMED => 0.90,
            self::UNCORROBORATED => 0.95,
            default => 1.0,
        };
    }

    private static function parseCollateralDamagePotential(?string $value): float
    {
        return match ($value) {
            self::LOW => 0.1,
            self::LOW_MEDIUM => 0.3,
            self::MEDIUM_HIGH => 0.4,
            self::HIGH => 0.5,
            default => 0,
        };
    }

    private static function parseTargetDistribution(?string $value): float
    {
        return match ($value) {
            self::NONE => 0,
            self::LOW => 0.25,
            self::MEDIUM => 0.75,
            default => 1.0,
        };
    }

    private static function parseSecurityRequirements(?string $value): float
    {
        return match ($value) {
            self::LOW => 0.5,
            self::HIGH => 1.51,
            default => 1.0,
        };
    }

    public static function parseBaseValuesAsArray(string $vector): array
    {
        $cvssObject = self::parseVector($vector);
        
        return [
            'accessVector' => self::findOptionalValueInVector($vector, self::BASE_ACCESS_VECTOR),
            'accessComplexity' => self::findOptionalValueInVector($vector, self::BASE_ATTACK_COMPLEXITY),
            'authentication' => self::findOptionalValueInVector($vector, self::BASE_AUTHENTICATION),
            'confidentiality' => self::findOptionalValueInVector($vector, self::BASE_CONFIDENTIALITY),
            'integrity' => self::findOptionalValueInVector($vector, self::BASE_INTEGRITY),
            'availability' => self::findOptionalValueInVector($vector, self::BASE_AVAILABILITY)
        ];

    }

}
