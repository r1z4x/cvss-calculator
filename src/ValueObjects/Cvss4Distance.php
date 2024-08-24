<?php

namespace Rootshell\CVSS\ValueObjects;

class CVSS4Distance
{
    public function __construct(
        public float $eqOne = 0.0,
        public float $eqTwo = 0.0,
        public float $eqThree = 0.0,
        public float $eqFour = 0.0,
        public float $eqFive = 0.0,
    ) {
    }
}
