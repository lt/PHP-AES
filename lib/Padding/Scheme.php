<?php

namespace AES\Padding;

interface Scheme
{
    function getPadding($message);
    function getPadLen($message);
} 
