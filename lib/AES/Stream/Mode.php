<?php

namespace AES\Stream;

use AES\Context;

interface Mode
{
    function encrypt(Context $ctx, $message, $final = false);
    function decrypt(Context $ctx, $message, $final = false);
}
