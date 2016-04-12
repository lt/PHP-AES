<?php declare(strict_types = 1);

namespace AES\Context;

use AES\Context;

class CBC extends Context
{
    public $key;
    public $state;
}
