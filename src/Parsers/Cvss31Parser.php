<?php

declare(strict_types=1);

namespace Rootshell\CVSS\Parsers;

use Rootshell\CVSS\Exceptions\CVSSException;
use Rootshell\CVSS\ValueObjects\CVSS23Object;

class CVSS31Parser
{
    private const NETWORK = 'N';
    private const ADJACENT = 'A';
    private const LOCAL = 'L';
    private const PHYSICAL = 'P';

    private const NONE = 'N';
    private const REQUIRED = 'R';

    private const LOW = 'L';
    private const MEDIUM = 'M';
    private const HIGH = 'H';

    private const NOT_DEFINED = 'X';
    private const FUNCTIONAL = 'F';
    private const PROOF_OF_CONCEPT = 'P';
    private const UNPROVEN = 'U';

    private const UNAVAILABLE = 'U';
    private const WORKAROUND = 'W';
    private const TEMPORARY_FIX = 'T';
    private const OFFICIAL_FIX = 'O';

    private const CONFIRMED = 'C';
    private const REASONABLE  = 'R';
    private const UNKNOWN = 'U';

    private const BASE_ATTACK_VECTOR = 'AV';
    private const BASE_ATTACK_COMPLEXITY = 'AC';
    private const BASE_PRIVILEGES_REQUIRED = 'PR';
    private const BASE_USER_INTERACTION = 'UI';
    private const BASE_SCOPE = 'S';
    private const BASE_CONFIDENTIALITY = 'C';
    private const BASE_INTEGRITY = 'I';
    private const BASE_AVAILABILITY = 'A';

    private const TEMPORAL_EXPLOIT_CODE_MATURITY = 'E';
    private const TEMPORAL_REMEDIATION_LEVEL = 'RL';
    private const TEMPORAL_REPORT_CONFIDENCE = 'RC';

    private const ENVIRONMENTAL_CONFIDENTIALITY_REQUIREMENT = 'CR';
    private const ENVIRONMENTAL_INTEGRITY_REQUIREMENT = 'IR';
    private const ENVIRONMENTAL_AVAILABILITY_REQUIREMENT = 'AR';
    private const ENVIRONMENTAL_MODIFIED_ATTACK_VECTOR = 'MAV';
    private const ENVIRONMENTAL_MODIFIED_ATTACK_COMPLEXITY = 'MAC';
    private const ENVIRONMENTAL_MODIFIED_PRIVILEGES_REQUIRED = 'MPR';
    private const ENVIRONMENTAL_MODIFIED_USER_INTERACTION = 'MUI';
    private const ENVIRONMENTAL_MODIFIED_SCOPE = 'MS';
    private const ENVIRONMENTAL_MODIFIED_CONFIDENTIALITY = 'MC';
    private const ENVIRONMENTAL_MODIFIED_INTEGRITY = 'MI';
    private const ENVIRONMENTAL_MODIFIED_AVAILABILITY = 'MA';

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
        $cvssObject->modifiedScope = $cvssObject->scope = self::findValueInVector($vector, self::BASE_SCOPE);
        $cvssObject->modifiedAttackVector = $cvssObject->attackVector = self::parseAttackVector(self::findValueInVector($vector, self::BASE_ATTACK_VECTOR));
        $cvssObject->modifiedAttackComplexity = $cvssObject->attackComplexity = self::parseAttackComplexity(self::findValueInVector($vector, self::BASE_ATTACK_COMPLEXITY));
        $cvssObject->modifiedPrivilegesRequired = $cvssObject->privilegesRequired = self::parsePrivilegesRequired(self::findValueInVector($vector, self::BASE_PRIVILEGES_REQUIRED), $cvssObject->scope);
        $cvssObject->modifiedUserInteraction = $cvssObject->userInteraction = self::parseUserInteraction(self::findValueInVector($vector, self::BASE_USER_INTERACTION));
        $cvssObject->modifiedConfidentiality = $cvssObject->confidentiality = self::parseConfidentialityIntegrityOrAvailability(self::findValueInVector($vector, self::BASE_CONFIDENTIALITY));
        $cvssObject->modifiedIntegrity = $cvssObject->integrity = self::parseConfidentialityIntegrityOrAvailability(self::findValueInVector($vector, self::BASE_INTEGRITY));
        $cvssObject->modifiedAvailability = $cvssObject->availability = self::parseConfidentialityIntegrityOrAvailability(self::findValueInVector($vector, self::BASE_AVAILABILITY));

        return $cvssObject;
    }

    private static function parseTemporalValues(string $vector, CVSS23Object $cvssObject): CVSS23Object
    {
        $cvssObject->exploitCodeMaturity = self::parseExploitCodeMaturity(self::findOptionalValueInVector($vector, self::TEMPORAL_EXPLOIT_CODE_MATURITY));
        $cvssObject->remediationLevel = self::parseRemediationLevel(self::findOptionalValueInVector($vector, self::TEMPORAL_REMEDIATION_LEVEL));
        $cvssObject->reportConfidence = self::parseReportConfidence(self::findOptionalValueInVector($vector, self::TEMPORAL_REPORT_CONFIDENCE));

        return $cvssObject;
    }

    private static function parseEnvironmentalValues(string $vector, CVSS23Object $cvssObject): CVSS23Object
    {
        $modifiedScopeValue = self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_MODIFIED_SCOPE);

        if (!is_null($modifiedScopeValue) && $modifiedScopeValue !== self::NOT_DEFINED) {
            $cvssObject->modifiedScope = $modifiedScopeValue;
        }

        $cvssObject->confidentialityRequirement = self::parseConfidentialityIntegrityOrAvailabilityRequirements(self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_CONFIDENTIALITY_REQUIREMENT));
        $cvssObject->integrityRequirement = self::parseConfidentialityIntegrityOrAvailabilityRequirements(self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_INTEGRITY_REQUIREMENT));
        $cvssObject->availabilityRequirement = self::parseConfidentialityIntegrityOrAvailabilityRequirements(self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_AVAILABILITY_REQUIREMENT));

        $modifiedAttackVectorValue = self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_MODIFIED_ATTACK_VECTOR);
        $modifiedAttackComplexityValue = self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_MODIFIED_ATTACK_COMPLEXITY);
        $modifiedPrivilegesRequiredValue = self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_MODIFIED_PRIVILEGES_REQUIRED);
        $modifiedUserInteractionValue = self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_MODIFIED_USER_INTERACTION);
        $modifiedConfidentialityValue = self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_MODIFIED_CONFIDENTIALITY);
        $modifiedIntegrityValue = self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_MODIFIED_INTEGRITY);
        $modifiedAvailabilityValue = self::findOptionalValueInVector($vector, self::ENVIRONMENTAL_MODIFIED_AVAILABILITY);

        if (!is_null($modifiedAttackVectorValue) && $modifiedAttackVectorValue !== self::NOT_DEFINED) {
            $cvssObject->modifiedAttackVector = self::parseAttackVector($modifiedAttackVectorValue);
        }

        if (!is_null($modifiedAttackComplexityValue) && $modifiedAttackComplexityValue !== self::NOT_DEFINED) {
            $cvssObject->modifiedAttackComplexity = self::parseAttackComplexity($modifiedAttackComplexityValue);
        }

        if (!is_null($modifiedPrivilegesRequiredValue) && $modifiedPrivilegesRequiredValue !== self::NOT_DEFINED) {
            $cvssObject->modifiedPrivilegesRequired = self::parsePrivilegesRequired($modifiedPrivilegesRequiredValue, $cvssObject->modifiedScope);
        }

        if (!is_null($modifiedUserInteractionValue) && $modifiedUserInteractionValue !== self::NOT_DEFINED) {
            $cvssObject->modifiedUserInteraction = self::parseUserInteraction($modifiedUserInteractionValue);
        }

        if (!is_null($modifiedConfidentialityValue) && $modifiedConfidentialityValue !== self::NOT_DEFINED) {
            $cvssObject->modifiedConfidentiality = self::parseConfidentialityIntegrityOrAvailability($modifiedConfidentialityValue);
        }

        if (!is_null($modifiedIntegrityValue) && $modifiedIntegrityValue !== self::NOT_DEFINED) {
            $cvssObject->modifiedIntegrity = self::parseConfidentialityIntegrityOrAvailability($modifiedIntegrityValue);
        }

        if (!is_null($modifiedAvailabilityValue) && $modifiedAvailabilityValue !== self::NOT_DEFINED) {
            $cvssObject->modifiedAvailability = self::parseConfidentialityIntegrityOrAvailability($modifiedAvailabilityValue);
        }

        return $cvssObject;
    }

    private static function findValueInVector(string $vector, string $section): string
    {
        $regex = '/(?<=\/' . $section . ':)(.)/';
        preg_match($regex, $vector, $matches);

        if (!isset($matches[0])) {
            throw CVSSException::missingValue();
        }

        return $matches[0];
    }

    private static function findOptionalValueInVector(string $vector, string $section): ?string
    {
        $regex = '/(?<=\/' . $section . ':)(.)/';
        preg_match($regex, $vector, $matches);

        return $matches[0] ?? null;
    }

    private static function parseAttackVector(string $value): float
    {
        return match ($value) {
            self::NETWORK => 0.85,
            self::ADJACENT => 0.62,
            self::LOCAL => 0.55,
            self::PHYSICAL => 0.2,
            default => throw CVSSException::invalidValue(),
        };
    }

    private static function parseAttackComplexity(string $value): float
    {
        return match ($value) {
            self::LOW => 0.77,
            self::HIGH => 0.44,
            default => throw CVSSException::invalidValue(),
        };
    }

    private static function parsePrivilegesRequired(string $value, string $scope): float
    {
        return match ($value) {
            self::NONE => 0.85,
            self::LOW => $scope === CVSS23Object::SCOPE_UNCHANGED ? 0.62 : 0.68,
            self::HIGH => $scope === CVSS23Object::SCOPE_UNCHANGED ? 0.27 : 0.5,
            default => throw CVSSException::invalidValue(),
        };
    }

    private static function parseUserInteraction(string $value): float
    {
        return match ($value) {
            self::NONE => 0.85,
            self::REQUIRED => 0.62,
            default => throw CVSSException::invalidValue(),
        };
    }

    private static function parseConfidentialityIntegrityOrAvailability(string $value): float
    {
        return match ($value) {
            self::HIGH => 0.56,
            self::LOW => 0.22,
            self::NONE => 0,
            default => throw CVSSException::invalidValue(),
        };
    }

    private static function parseExploitCodeMaturity(?string $value): float
    {
        return match ($value) {
            self::FUNCTIONAL => 0.97,
            self::PROOF_OF_CONCEPT => 0.94,
            self::UNPROVEN => 0.91,
            default => 1,
        };
    }

    private static function parseRemediationLevel(?string $value): float
    {
        return match ($value) {
            self::WORKAROUND => 0.97,
            self::TEMPORARY_FIX => 0.96,
            self::OFFICIAL_FIX => 0.95,
            default => 1,
        };
    }

    private static function parseReportConfidence(?string $value): float
    {
        return match ($value) {
            self::REASONABLE => 0.96,
            self::UNKNOWN => 0.92,
            default => 1,
        };
    }

    private static function parseConfidentialityIntegrityOrAvailabilityRequirements(?string $value): float
    {
        return match ($value) {
            self::HIGH => 1.5,
            self::LOW => 0.5,
            default => 1,
        };
    }

    public static function parseBaseValuesAsArray(string $vector): array
    {
        $cvssObject = self::parseVector($vector);

        return [
            'attackVector' => self::findOptionalValueInVector($vector, self::BASE_ATTACK_VECTOR),
            'attackComplexity' => self::findOptionalValueInVector($vector, self::BASE_ATTACK_COMPLEXITY),
            'privilegesRequired' => self::findOptionalValueInVector($vector, self::BASE_PRIVILEGES_REQUIRED),
            'userInteraction' => self::findOptionalValueInVector($vector, self::BASE_USER_INTERACTION),
            'scope' => self::findOptionalValueInVector($vector, self::BASE_SCOPE),
            'confidentiality' => self::findOptionalValueInVector($vector, self::BASE_CONFIDENTIALITY),
            'integrity' => self::findOptionalValueInVector($vector, self::BASE_INTEGRITY),
            'availability' => self::findOptionalValueInVector($vector, self::BASE_AVAILABILITY)
        ];
    }
}
