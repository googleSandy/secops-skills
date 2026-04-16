# Source: https://docs.cloud.google.com/chronicle/docs/yara-l/functions

# Functions
Supported in:    Google secops   SIEM
This section describes the YARA-L 2.0 functions that you can use in Rules, Search, and Dashboard queries.
For details about aggregate functions, see Statistics and aggregations in search. Note: The use of the event variable `$e` is optional when YARA-L is used in Search and Dashboards. Both `principal.hostname` and `$e.principal.hostname` are supported in Search and Dashboards.
You can use these functions in the following parts of a YARA-L query:  `events` section `BOOL_CLAUSE` of a conditional in the outcome section   .supported-container { display: flex; gap: 7px; }
### arrays.concat
Supported in:    Rules   Search
```
arrays.concat(string_array, string_array)

```
#### Description
Returns a new string array by copying elements from original string arrays.
#### Param data types
`ARRAY_STRINGS`, `ARRAY_STRINGS`
#### Return type
`ARRAY_STRINGS`
#### Code samples
##### Example 1
The following example concatenates two different string arrays.
```
arrays.concat(["test1", "test2"], ["test3"]) = ["test1", "test2", "test3"]

```
##### Example 2
The following example concatenates arrays with empty string.
```
arrays.concat([""], [""]) = ["", ""]

```
##### Example 3
The following example concatenates empty arrays.
```
arrays.concat([], []) = []

```
.supported-container { display: flex; gap: 7px; }
### arrays.index_to_float
Supported in:    Rules   Search
```
arrays.index_to_float(array, index)

```
#### Description
Returns the element at the given index of an array. The element at that index is returned as a float.
The index is an integer value which represents the position of an element in the array. By default, the first element of an array has an index of 0, and the last element has an index of n-1, where n is the size of the array. Negative indexing allows accessing array elements relative to the end of the array. For example, an index of -1 refers to the last element in the array and an index of -2 refers to the second to last element in the array.
#### Param data types
`ARRAY_STRINGS|ARRAY_INTS|ARRAY_FLOATS`, `INT`
#### Return type
`FLOAT`
#### Code samples
##### Example 1
The following example fetches an element at index 1 from an array of floats.
```
arrays.index_to_float([1.2, 2.1, 3.5, 4.6], 1) // 2.1

```
##### Example 2
The following example fetches an element at index -1 from an array of floats.
```
arrays.index_to_float([1.2, 2.1, 3.5, 4.6], 0-1) // 4.6

```
##### Example 3
The following example fetches an element for an index greater than the size of the array.
```
arrays.index_to_float([1.2, 2.1, 3.5, 4.6], 6) // 0.0

```
##### Example 4
The following example fetches an element from an empty array.
```
arrays.index_to_float([], 0) // 0.0

```
##### Example 5
The following example fetches an element at index 1 from a string array.
```
arrays.index_to_float(["1.2", "3.3", "2.4"], 1) // 3.3

```
##### Example 6
The following example fetches an element at index 2 from an array of integers.
```
arrays.index_to_float([1, 3, 2], 2) // 2.0

```
.supported-container { display: flex; gap: 7px; }
### arrays.index_to_int
Supported in:    Rules   Search
```
arrays.index_to_int(array_of_inputs, index)

```
#### Description
Returns the value at a given index in an array as an integer.
The index is an integer value which represents the position of an element in the array. By default, the first element of an array has an index of 0, and the last element has an index of n-1, where n is the size of the array. Negative indexing allows accessing array elements relative to the end of the array. For example, an index of -1 refers to the last element in the array and an index of -2 refers to the second to last element in the array.
#### Param data types
`ARRAY_STRINGS|ARRAY_INTS|ARRAY_FLOATS`, `INT`
#### Return type
`INT`
#### Code samples
##### Example 1
This function call returns 0 when the value at the index is a non-numeric string.
```
arrays.index_to_int(["str0", "str1", "str2"], 1) = 0

```
##### Example 2
This function returns the element at index -1.
```
arrays.index_to_int(["44", "11", "22", "33"], 0-1) = 33

```
##### Example 3
Returns 0 for the out-of-bounds element.
```
arrays.index_to_int(["44", "11", "22", "33"], 5) = 0

```
##### Example 4
This function fetches the element from the float array at index 1.
```
arrays.index_to_int([1.100000, 1.200000, 1.300000], 1) = 1

```
##### Example 5
This function fetches the element from the int array at index 0.
```
arrays.index_to_int([1, 2, 3], 0) = 1

```
.supported-container { display: flex; gap: 7px; }
### arrays.index_to_str
Supported in:    Rules   Search
```
arrays.index_to_str(array, index)

```
#### Description
Returns the element at the given index from the array as a string. The index is an integer value that represents the position of an element in the array. By default, the first element of an array has an index of 0, and the last element has an index of n-1, where n is the size of the array. Negative indexing allows accessing array elements from the end of the array. For example, an index of -1 refers to the last element in the array and an index of -2 refers to the second to last element in the array.
#### Param data types
`ARRAY_STRINGS|ARRAY_INTS|ARRAY_FLOATS`, `INT`
#### Return type
`STRING`
#### Code samples
##### Example 1
The following example fetches an element at index 1 from an array of strings.
```
arrays.index_to_str(["test1", "test2", "test3", "test4"], 1) // "test2"

```
##### Example 2
The following example fetches an element at index -1 (last element of the array) from an array of strings.
```
arrays.index_to_str(["test1", "test2", "test3", "test4"], 0-1) // "test4"

```
##### Example 3
The following example fetches an element for an index greater than the size of the array, which returns an empty string.
```
arrays.index_to_str(["test1", "test2", "test3", "test4"], 6) // ""

```
##### Example 4
The following example fetches an element from an empty array.
```
arrays.index_to_str([], 0) // ""

```
##### Example 5
The following example fetches an element at index 0 from an array of floats. The output is returned as a string.
```
arrays.index_to_str([1.200000, 3.300000, 2.400000], 0) // "1.2"

```
##### Example 6
The following example fetches an element at index 2 from an array of integers. The output is in the form of a string.
```
arrays.index_to_str([1, 3, 2], 2) // "2"

```
.supported-container { display: flex; gap: 7px; }
### arrays.join_string
Supported in:    Rules   Search
```
arrays.join_string(array_of_strings, optional_delimiter)

```
#### Description
Converts an array of strings into a single string separated by the optional parameter. If no delimiter is provided, the empty string is used.
#### Param data types
`ARRAY_STRINGS`, `STRING`
#### Return type
`STRING`
#### Code samples
Here are some examples of how to use the function:
##### Example 1
This example joins an array with non-null elements and a delimiter.
```
arrays.join_string(["foo", "bar"], ",") = "foo,bar"

```
##### Example 2
This example joins an array with a null element and a delimiter.
```
arrays.join_string(["foo", NULL, "bar"], ",") = "foo,bar"

```
##### Example 3
This example joins an array with non-null elements and no delimiter.
```
arrays.join_string(["foo", "bar"]) = "foobar"

```
.supported-container { display: flex; gap: 7px; }
### arrays.length
Supported in:    Rules   Search
```
arrays.length(repeatedField)

```
#### Description
Returns the number of repeated field elements.
#### Param data types
`LIST`
#### Return type
`NUMBER`
#### Code samples
##### Example 1
Returns the number of repeated field elements.
```
arrays.length($e.principal.ip) = 2

```
##### Example 2
If multiple repeated fields are along the path, returns the total number of repeated field elements.
```
arrays.length($e.intermediary.ip) = 3

```
.supported-container { display: flex; gap: 7px; }
### arrays.max
Supported in:    Rules   Search
```
arrays.max(array_of_ints_or_floats)

```
#### Description
Returns the greatest element in an array or zero if the array is empty.
#### Param data types
`ARRAY_INTS|ARRAY_FLOATS`
#### Return type
`FLOAT`
#### Code samples
Here are some examples of how to use the function:
##### Example 1
This example returns the greater element in an array of integers.
```
arrays.max([10, 20]) = 20.000000

```
##### Example 2
This example returns the greater element in an array of floats.
```
arrays.max([10.000000, 20.000000]) = 20.000000

```
.supported-container { display: flex; gap: 7px; }
### arrays.min
Supported in:    Rules   Search
```
arrays.min(array_of_ints_or_floats[, ignore_zeros=false])

```
#### Description
Returns the smallest element in an array or zero if the array is empty. If the second, optional argument is set to true, elements equal to zero are ignored.
#### Param data types
`ARRAY_INTS|ARRAY_FLOATS`, `BOOL`
#### Return type
`FLOAT`
#### Code samples
Here are some examples of how to use the function:
##### Example 1
This example returns the smallest element in an array of integers.
```
arrays.min([10, 20]) = 10.000000

```
##### Example 2
This example returns the smallest element in an array of floats.
```
arrays.min([10.000000, 20.000000]) = 10.000000

```
##### Example 3
This example returns the smallest element in an array of floats, while ignoring the zeroes.
```
arrays.min([10.000000, 20.000000, 0.0], true) = 10.000000

```
.supported-container { display: flex; gap: 7px; }
### arrays.size
Supported in:    Rules   Search
```
arrays.size( array )

```
#### Description
Returns the size of the array. Returns 0 for an empty array.
#### Param data types
`ARRAY_STRINGS|ARRAY_INTS|ARRAY_FLOATS`
#### Return type
`INT`
#### Code samples
##### Example 1
This example uses a string array that contains two elements.
```
arrays.size(["test1", "test2"]) = 2

```
##### Example 2
This example uses an int array that contains 3 elements.
```
arrays.size([1, 2, 3]) = 3

```
##### Example 3
This example uses a float array thats contains 1 elements
```
arrays.size([1.200000]) = 1

```
##### Example 4
This example uses an empty array.
```
arrays.size([]) = 0

```
.supported-container { display: flex; gap: 7px; }
### bytes.to_base64
Supported in:    Rules   Search
```
bytes.to_base64(bytes, optional_default_string)

```
#### Description
Function converts a `bytes` value to a `base64 encoded string`. Function calls with values that cannot be casted return an empty string by default.
#### Param data types
`BYTES`, `STRING`
#### Return type
`STRING`
#### Code samples
##### Raw Binary Bytes to Base64 Encoded String
The function converts the raw binary bytes to base64 encoded string.
```
bytes.to_base64(b'000000006f8ec5586d026f9ddac56e9f2fe15b8a0000000001000000cd000000) = "AAAAAG+OxVhtAm+d2sVuny/hW4oAAAAAAQAAAM0AAAA="

```
##### Failed Conversion (Defaults to the Optionally Provided String)
The function defaults to the `"invalid bytes"` when the bytes value provided isn't valid.
```
bytes.to_base64(b'000000006f8ec5586d", "invalid bytes") = "invalid bytes"

```
.supported-container { display: flex; gap: 7px; }
### cast.as_bool
Supported in:    Rules   Search
```
cast.as_bool(string_or_int)

```
#### Description
Function converts an int or string value into a bool value. Function calls with values that cannot be casted will return FALSE. Returns TRUE only for integer 1 and case insensitive string 'true'.
#### Param data types
`INT|STRING`
#### Return type
`BOOL`
#### Code samples
##### Example 1
This example shows how to cast a non-boolean string
```
cast.as_bool("123") = false

```
##### Example 2
Truthy integer (1)
```
cast.as_bool(1) = true

```
##### Example 3
Truthy string
```
cast.as_bool("true") = true

```
##### Example 4
Capital truthy string
```
cast.as_bool("TRUE") = true

```
##### Example 5
Negative integer
```
cast.as_bool(0-1) = false

```
##### Example 6
False integer (0)
```
cast.as_bool(0) = false

```
##### Example 7
empty string
```
cast.as_bool("") = false

```
.supported-container { display: flex; gap: 7px; }
### cast.as_float
Supported in:    Rules   Search
```
cast.as_float(string_to_cast)

```
#### Description
Converts a numeric string into a float. Any function calls with values that cannot be casted return 0. Floats maintain precision up to 7 decimal digits.
#### Param data types
`STRING`
#### Return type
`FLOAT`
#### Code samples
##### Example 1
Casting a non-numeric string returns 0.
```
cast.as_float("str") = 0.0000000

```
##### Example 2
Casting an empty string returns 0.
```
cast.as_float("") = 0.0000000

```
##### Example 3
Casting a valid numeric string returns a float value.
```
cast.as_float("1.012345678") = 1.0123456

```
.supported-container { display: flex; gap: 7px; }
### cast.as_int
Supported in:    Rules   Search
```
cast.as_int(string_to_cast)

```
#### Description
Converts a numeric string into an integer. Any function calls with values that cannot be cast return 0.
#### Param data types
`STRING`
#### Return type
`FLOAT`
#### Code samples
##### Example 1
Casting a non-numeric string returns 0.
```
cast.as_int("str") = 0

```
##### Example 2
Casting an empty string returns 0.
```
cast.as_int("") = 0

```
##### Example 3
Casting a valid numeric string returns an integer value.
```
cast.as_int("2.012345678") = 2

```
.supported-container { display: flex; gap: 7px; }
### cast.as_string
Supported in:    Rules   Search
```
cast.as_string(int_or_bytes_or_bool, optional_default_string)

```
#### Description
The `cast.as_string` function transforms an `INT`, `BYTES`, or `BOOL` value into its string representation. You can provide an optional `default_string` argument to handle cases where the cast fails. If you omit the `default_string` argument, or if the input is an invalid `UTF-8` or `BASE64` byte sequence, the function returns an empty string.
#### Param data types
`INT|BYTES|BOOL`, `STRING`
#### Return type
`STRING`
#### Code samples
##### Integer to String Conversion
The function converts the integer `123` to the string `"123"`.
```
cast.as_string(123) = "123"

```
##### Bytes to String Conversion
The function converts the raw binary `b'01` to the string `"\x01"`.
```
cast.as_string(b'01, "") = "\x01"

```
##### Boolean to String Conversion
The function converts the boolean `true` to the string `"true"`.
```
cast.as_string(true, "") = "true"

```
##### Failed Conversion (Defaults to the Optionally Provided String)
The function defaults to the string `"casting error"` when the value provided is invalid.
```
cast.as_string(9223372036854775808, "casting error") = "casting error"

```
.supported-container { display: flex; gap: 7px; }
### fingerprint
Supported in:    Rules
```
hash.fingerprint2011(byteOrString)

```
#### Description
This function calculates the `fingerprint2011` hash of an input byte sequence or string. This function returns an unsigned `INT` value in the range `[2, 0xFFFFFFFFFFFFFFFF]`. Note: This function shouldn't be used as a cryptographic secure hash.
#### Param data types
`BTYE`, `STRING`
#### Return type
`INT`
#### Code sample
```
id_fingerprint = hash.fingerprint2011("user123")

```
.supported-container { display: flex; gap: 7px; }
### group
Supported in:    Search
```
group(field1, field2, field3, ...)

```
#### Description
Group fields of a similar type into a placeholder variable.
In UDM search, grouped fields are used to search across multiple fields of a similar type. The group function is similar to grouped fields except that it lets you select which fields you want grouped together to trigger a detection. You can use the group function for gathering information about a specific entity (for example, a hostname, IP address, or userid) across different Noun types. Note: For search, you can use grouped fields in the `events` section, but not in the `match` and `outcome` sections. For more details, `events` section syntax, `match` section syntax, and `outcome` section syntax.
Parameter type: `Event type`
Return type: `Grouped event fields`
#### Code samples
Example: Aggregate and count IP addresses
Group all IP addresses together and provide a descending count of the most prevalent IP addresses in the time range scanned.
```
$ip = group(principal.ip, about.ip, target.ip)
$ip != ""
match:
  $ip

outcome:
  $count = count_distinct(metadata.id)

order:
  $count desc

```
Example: Count distinct events for each IP address
In the following example, the `group()` function gathers all the IP addresses found in the `principal.ip`, `target.ip`, and `src.ip` fields across all events that triggered the detection. The IP addresses are then added to the placeholder variable `$ip`. The rule then matches the IP address and returns a count of distinct events for each unique IP address.
```
$ip = group(detection.collection_elements.references.event.principal.ip, detection.collection_elements.references.event.target.ip, detection.collection_elements.references.event.src.ip)
$ip != ""

match:
  $ip

outcome:
  $count = count_distinct(detection.id)

order:
  $count desc

// Detection1: principal.ip = 1.1.1.1
// Detection2: src.ip = 1.1.1.1, target.ip = 2.2.2.2
// Detection3: target.ip = 1.1.1.1
// Detection4: principal.ip = 2.2.2.2

```
Result:    `$ip` `$count`     1.1.1.1 3   2.2.2.2 2     .supported-container { display: flex; gap: 7px; }
### hash.sha256
Supported in:    Rules
```
hash.sha256(string)

```
#### Description
Returns a SHA-256 hash of the input string.
#### Param data types
`STRING`
#### Return type
`STRING`
#### Code samples
##### Example 1
This example shows the SHA-256 hash when the input is a valid string.
```
hash.sha256("str") = "8c25cb3686462e9a86d2883c5688a22fe738b0bbc85f458d2d2b5f3f667c6d5a"

```
##### Example 2
This example shows the SHA-256 hash when the input is an empty string.
```
hash.sha256("") = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

```
.supported-container { display: flex; gap: 7px; }
### math.abs
Supported in:    Rules   Search
```
math.abs(numericExpression)

```
#### Description
Returns the absolute value of an integer or float expression.
#### Param data types
`NUMBER`
#### Return type
`NUMBER`
#### Code samples
##### Example 1
This example returns True if the event was more than 5 minutes from the time specified (in seconds from the Unix epoch), regardless of whether the event came before or after the time specified. A call to `math.abs` cannot depend on multiple variables or placeholders. For example, you cannot replace the hardcoded time value of 1643687343 in the following example with `$e2.metadata.event_timestamp.seconds`.
```
300 < math.abs($e1.metadata.event_timestamp.seconds - 1643687343)

```
.supported-container { display: flex; gap: 7px; }
### math.ceil
Supported in:    Rules   Search
```
math.ceil(number)

```
#### Description
Returns the smallest integer that is not less than the given number (rounding up). Will return 0 if the input is null or too big to fit in an int64.
#### Param data types
`FLOAT`
#### Return type
`INT`
#### Code samples
This section contains examples of using `math.ceil`.
##### Example 1
This example returns the ceil of a whole number.
```
math.ceil(2.000000) = 2

```
##### Example 2
This example returns the ceil of a negative number.
```
math.ceil(0-1.200000) = -1

```
##### Example 3
This example returns 0 as the ceil of a number that is too big for a 64 bit integer.
```
math.ceil(184467440737095516160.0) = 0

```
.supported-container { display: flex; gap: 7px; }
### math.floor
Supported in:    Rules   Search
```
math.floor(float_val)

```
#### Description
Returns the largest integer value that is not greater than the supplied value (rounding down). Returns 0 if the input is null or too large to fit into an int64.
#### Param data types
`FLOAT`
#### Return type
`INT`
#### Code samples
##### Example 1
This example shows a positive number case.
```
math.floor(1.234568) = 1

```
##### Example 2
This example shows a negative number case.
```
math.floor(0-1.234568) = -2

```
##### Example 3
This example shows a zero case.
```
math.floor(0.000000) = 0

```
.supported-container { display: flex; gap: 7px; }
### math.geo_distance
Supported in:    Rules
```
math.geo_distance(longitude1, latitude1, longitude2, latitude2))

```
#### Description
Returns the distance between two geographic locations (coordinates) in meters. Returns -1 if the coordinates are invalid.
#### Parameter data types
`FLOAT`, `FLOAT`, `FLOAT`, `FLOAT`
#### Return type
`FLOAT`
#### Code samples
##### Example 1
The following example returns the distance when all parameters are valid coordinates:
```
math.geo_distance(-122.020287, 37.407574, -122.021810, 37.407574) = 134.564318

```
##### Example 2
The following example returns the distance when one of the parameters is a truncated coordinate:
```
math.geo_distance(-122.000000, 37.407574, -122.021810, 37.407574) = 1926.421905

```
##### Example 3
The following example returns `-1` when one of the parameters is an invalid coordinate:
```
math.geo_distance(0-122.897680, 37.407574, 0-122.021810, 97.407574) = -1.000000

```
##### Example 4
The following example returns `0` when coordinates are the same:
```
math.geo_distance(-122.897680, 37.407574, -122.897680, 37.407574) = 0.000000

```
.supported-container { display: flex; gap: 7px; }
### math.is_increasing
Supported in:    Rules   Search
```
math.is_increasing(num1, num2, num3)

```
#### Description
Takes a list of numeric values (integers or doubles) and returns `True` if the values are in ascending order, and `False` otherwise.
#### Param data types
`INT|FLOAT`, `INT|FLOAT`, `INT|FLOAT`
#### Return type
`BOOL`
#### Code samples
##### Example 1
This example includes timestamp-like values in seconds.
```
math.is_increasing(1716769112, 1716769113, 1716769114) = true

```
##### Example 2
This example includes one negative double, one zero INT64, and one positive INT64 values.
```
math.is_increasing(-1.200000, 0, 3) = true

```
##### Example 3
This example includes one negative double, one zero INT64, and one negative INT64 values.
```
math.is_increasing(0-1.200000, 0, 0-3) = false

```
##### Example 4
This example includes two negative doubles and one zero INT64 value.
```
math.is_increasing(0-1.200000, 0-1.50000, 0) = false

```
##### Example 5
This example includes one negative double and two values that are the same.
```
math.is_increasing(0-1.200000, 0, 0) = false

```
.supported-container { display: flex; gap: 7px; }
### math.log
Supported in:    Rules   Search
```
math.log(numericExpression)

```
#### Description
Returns the natural log value of an integer or float expression.
#### Param data types
`NUMBER`
#### Return type
`NUMBER`
#### Code samples
##### Example 1
```
math.log($e1.network.sent_bytes) > 20

```
.supported-container { display: flex; gap: 7px; }
### math.pow
Supported in:    Rules   Search
```
math.pow(base, exponent)

```
#### Description
Returns the value of the first arg raised to the power of the second arg. Returns 0 in case of overflow.
#### Param data types
base: `INT|FLOAT` exponent: `INT|FLOAT`
#### Return type
`FLOAT`
#### Code samples
##### Example 1
This example shows an integer case.
```
math.pow(2, 2) // 4.00

```
##### Example 2
This example shows a fraction base case.
```
math.pow(2.200000, 3) // 10.648

```
##### Example 3
This example shows a fraction base and power case.
```
math.pow(2.200000, 1.200000) // 2.575771

```
##### Example 4
This example shows a negative power case.
```
math.pow(3, 0-3) // 0.037037

```
##### Example 5
This example shows a fraction power case.
```
math.pow(3, 0-1.200000) // 0.267581

```
##### Example 6
This example shows a negative base case.
```
math.pow(0-3, 0-3) // -0.037037

```
##### Example 7
This example shows a zero base case.
```
math.pow(0, 3) // 0

```
##### Example 8
This example shows a zero power case.
```
math.pow(9223372036854775807, 0) // 1

```
##### Example 9
This example shows a large base case.
```
math.pow(9223372036854775807, 1.200000) // 57262152889751593549824

```
.supported-container { display: flex; gap: 7px; }
### math.random
Supported in:    Rules   Search
```
math.random()

```
#### Description
Generates a pseudo-random value of type DOUBLE in the range of `[0, 1)`, inclusive of 0 and exclusive of 1.
#### Return type
`FLOAT`
#### Code samples
The following example checks whether the random value is in the range `[0, 1)`. `none if(math.random() >= 0 and math.random() < 1) = true`  .supported-container { display: flex; gap: 7px; }
### math.round
Supported in:    Search
```
math.round(numericExpression, decimalPlaces)

```
#### Description
Returns a value rounded to the nearest integer or to the specified number of decimal places.
#### Param data types
`NUMBER`
#### Return type
`NUMBER`
#### Code samples
```
math.round(10.7) // returns 11
math.round(1.2567, 2) // returns 1.25
math.round(0-10.7) // returns -11
math.round(0-1.2) // returns -1
math.round(4) // returns 4, math.round(integer) returns the integer

```
.supported-container { display: flex; gap: 7px; }
### math.sqrt
Supported in:    Rules   Search
```
math.sqrt(number)

```
#### Description
Returns the square root of the given number. Returns 0 in case of negative numbers.
#### Param data types
`INT|FLOAT`
#### Return type
`FLOAT`
#### Code samples
##### Example 1
This example returns the square root of an int argument.
```
math.sqrt(3) = 1.732051

```
##### Example 2
This example returns the square root of a negative int argument.
```
math.sqrt(-3) = 0.000000

```
##### Example 3
This example returns the square root of zero argument.
```
math.sqrt(0) = 0.000000

```
##### Example 4
This example returns the square root of a float argument.
```
math.sqrt(9.223372) = 3.037000

```
##### Example 5
This example returns the square root of a negative float argument.
```
math.sqrt(0-1.200000) = 0.000000

```
.supported-container { display: flex; gap: 7px; }
### metrics
Supported in:    Rules
Metrics functions can aggregate large amounts of historical data. You can use this in your rule using `metrics.functionName()` in the outcome section.
For more information, see YARA-L Metrics.  .supported-container { display: flex; gap: 7px; }
### net.ip_in_range_cidr
Supported in:    Rules   Search
```
net.ip_in_range_cidr(ipAddress, subnetworkRange)

```
#### Description
Returns `true` when the given IP address is within the specified subnetwork.
You can use YARA-L to search for UDM events across all of the IP addresses within a subnetwork using the `net.ip_in_range_cidr()` statement. Both IPv4 and IPv6 are supported.
To search across a range of IP addresses, specify an IP UDM field and a CIDR range. YARA-L can handle both singular and repeating IP address fields.
To search across a range of IP addresses, specify an `ip` UDM field and a Classless Inter-Domain Routing (CIDR) range. YARA-L can handle both singular and repeating IP address fields.
#### Param data types
`STRING`, `STRING`
#### Return type
`BOOL`
#### Code samples
##### Example 1
IPv4 example:
```
net.ip_in_range_cidr($e.principal.ip, "192.0.2.0/24")

```
##### Example 2
IPv6 example:
```
net.ip_in_range_cidr($e.network.dhcp.yiaddr, "2001:db8::/32")

```
For an example rule using the `net.ip_in_range_cidr()`statement, see the example rule in Single Event within Range of IP Addresses.)  .supported-container { display: flex; gap: 7px; }
### re.regex
Supported in:    Rules   Search
You can define regular expression matching in YARA-L 2.0 using either of the following syntax:
Using YARA-L syntax — Related to events. The following is a generic representation of this syntax:
```
$e.field = /regex/

```
Using YARA-L syntax — As a function taking in the following parameters:  Field the regular expression is applied to. Regular expression specified as a string.
The following is a generic representation of this syntax:
```
re.regex($e.field, `regex`)

```
#### Description
This function returns `true` if the string contains a substring that matches the regular expression provided. It is unnecessary to add `.*` to the beginning or at the end of the regular expression.
##### Notes
To match the exact string or only a prefix or suffix, include the `^` (starting) and `$` (ending) anchor characters in the regular expression. For example, `/^full$/` matches `"full"` exactly, while `/full/` could match `"fullest"`, `"lawfull"`, and `"joyfully"`. If the UDM field includes newline characters, the `regexp` only matches the first line of the UDM field. To enforce full UDM field matching, add a `(?s)` to the regular expression. For example, replace `/.*allUDM.*/` with `/(?s).*allUDM.*/`. You can use the `nocase` modifier after strings to indicate that the search should ignore capitalization.
#### Param data types
`STRING`, `STRING`
#### Param expression types
`ANY`, `ANY`
#### Return type
`BOOL`
#### Code samples
##### Example 1
```
// Equivalent to $e.principal.hostname = /google/
re.regex($e.principal.hostname, "google")

```
.supported-container { display: flex; gap: 7px; }
### re.capture
Supported in:    Rules   Search
```
re.capture(stringText, regex)

```
#### Description
Captures (extracts) data from a string using the regular expression pattern provided in the argument.
This function takes two arguments:  `stringText`: the original string to search. `regex`: the regular expression indicating the pattern to search for.
The regular expression can contain 0 or 1 capture groups in parentheses. If the regular expression contains 0 capture groups, the function returns the first entire matching substring. If the regular expression contains 1 capture group, it returns the first matching substring for the capture group. Defining two or more capture groups returns a compiler error.
#### Param data types
`STRING`, `STRING`
#### Return type
`STRING`
#### Code samples
##### Example 1
In this example, if `$e.principal.hostname` contains "aaa1bbaa2" the following would be true, because the function returns the first instance. This example has no capture groups.
```
"aaa1" = re.capture($e.principal.hostname, "a+[1-9]")

```
##### Example 2
This example captures everything after the @ symbol in an email. If the `$e.network.email.from` field is `test@google.com`, the example returns `google.com`. The following example contains one capture group.
```
"google.com" = re.capture($e.network.email.from , "@(.*)")

```
##### Example 3
If the regular expression does not match any substring in the text, the function returns an empty string. You can omit events where no match occurs by excluding the empty string, which is especially important when you are using `re.capture()` with an inequality:
```
// Exclude the empty string to omit events where no match occurs.
"" != re.capture($e.network.email.from , "@(.*)")

// Exclude a specific string with an inequality.
"google.com" != re.capture($e.network.email.from , "@(.*)")

```
.supported-container { display: flex; gap: 7px; }
### re.capture_all
Supported in:    Rules   Search   Dashboards
```
re.capture_all(stringText, regex)

```
#### Description
Use the `re.capture_all()` function to extract every non-overlapping match of a regular expression from a string. While the standard `re.capture()` function stops after the first match it finds, `re.capture_all()` continues through the entire string to identify every instance that matches your pattern.
This function takes two arguments:  `string_to_search`: The input string or UDM field you want to search. `regex_pattern`: The regular expression you apply. Note: This regular expression must not contain more than one capturing group.
#### Common use cases
You use `re.capture_all()` to solve scenarios where a single log field contains multiple valuable data points.  Extract multiple indicators: Pull all IP addresses, URLs, or hostnames from a single log message or description field. Parse delimited data: Isolate specific values from fields where multiple pieces of information are separated by commas, semicolons, or mixed with other text. Analyze free-form text: Scan unstructured fields (like Notes or Comments) to identify every pattern match, such as file paths or registry keys. Audit command lines: Extract all arguments or specific flags from a process command line to better understand the scope of a command.
#### Param data types
`STRING`, `STRING`
#### Return type
`ARRAY_STRINGS`
#### Examples
This section shows examples that demonstrate how you apply `re.capture_all()` to different types of telemetry. You use these patterns in the `events` section to filter data or the `outcome` section to enrich your final detection alerts.
##### Example: Extract the fifth .conf path from a command line
This search example first confirms the presence of `.conf` in a command line.
It then saves the full command line and extracts the fifth occurrence of a specific pattern related to `.conf` file paths. You can combine the `re.capture_all()` function with `arrays.index_to_str()` to extract a specific occurrence, such as the fifth `.conf` path from a command line.
```
re.regex(principal.process.command_line, `\.conf`)
$command_line = principal.process.command_line
$path_component_5 = arrays.index_to_str(re.capture_all(principal.process.command_line, `[s='"]([^'"=s]*.conf)`), 4)

```
Note: If the `re.capture_all()` function finds fewer than five matches, index 4 is out of bounds. In this case, `arrays.index_to_str()` returns an empty string `""` for `$path_component_5`.
##### Example: Extract all words that start with `error`
In this rule example, you capture every word starting with `error` from a security result description and store them in an array called `$all_errors`.
```
rule ExtractErrors {
  meta:
    author = "user@example.com"
  events:
    $e.principal.hostname = "server1"
    $log_message = $e.security_result[0].description
  outcome:
    $all_errors = re.capture_all($log_message, `error\w+`)
  condition:
    $e
}

```
##### Example: Join all captured IP-like patterns from a User-Agent string
In this rule example, you extract all IPv4 addresses from the `network.http.user_agent` field of security events.
Since `re.capture_all()` returns an array, you can use `arrays.join_string()` to merge these matches into a single, readable list.
```
rule CaptureAllIPs {
  meta:
    author = "user@example.com"
  events:
    $e.network.http.user_agent != ""
    $captured_ips = arrays.join_string(re.capture_all($e.network.http.user_agent, `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`), ", ")
  condition:
    $e
}

```
#### Known limitations
Single capturing group: The regular expression used with `re.capture_all()` must not contain more than one capturing group. Array return type: The function returns an array of strings. To assign the result to an event variable or to use it in functions expecting a single string, you typically need to wrap it with `arrays.join_string()`.    .supported-container { display: flex; gap: 7px; }
### re.replace
Supported in:    Rules   Search
```
re.replace(stringText, replaceRegex, replacementText)

```
#### Description
Performs a regular expression replacement.
This function takes three arguments:  `stringText`: the original string. `replaceRegex`: the regular expression indicating the pattern to search for. `replacementText`: The text to insert into each match.
Returns a new string derived from the original `stringText`, where all substrings that match the pattern in `replaceRegex` are replaced with the value in `replacementText`. You can use backslash-escaped digits (`\1` to `\9`) within `replacementText` to insert text matching the corresponding parenthesized group in the `replaceRegex` pattern. Use `\0` to refer to the entire matching text.
The function replaces non-overlapping matches and will prioritize replacing the first occurrence found. For example, `re.replace("banana", "ana", "111")` returns the string "b111na".
#### Param data types
`STRING`, `STRING`, `STRING`
#### Return type
`STRING`
#### Code samples
##### Example 1
This example captures everything after the `@` symbol in an email, replaces `com` with `org`, and then returns the result. Notice the use of nested functions.
```
"email@google.org" = re.replace($e.network.email.from, "com", "org")

```
##### Example 2
This example uses backslash-escaped digits in the `replacementText` argument to reference matches to the `replaceRegex` pattern.
```
"test1.com.google" = re.replace(
                       $e.principal.hostname, // holds "test1.test2.google.com"
                       "test2\.([a-z]*)\.([a-z]*)",
                       "\\2.\\1"  // \\1 holds "google", \\2 holds "com"
                     )

```
##### Example 3
Note the following cases when dealing with empty strings and `re.replace()`:
Using empty string as `replaceRegex`:
```
// In the function call below, if $e.principal.hostname contains "name",
// the result is: 1n1a1m1e1, because an empty string is found next to
// every character in `stringText`.
re.replace($e.principal.hostname, "", "1")

```
To replace an empty string, you can use `"^$"` as `replaceRegex`:
```
// In the function call below, if $e.principal.hostname contains the empty
// string, "", the result is: "none".
re.replace($e.principal.hostname, "^$", "none")

```
.supported-container { display: flex; gap: 7px; }
### sample_rate
Supported in:    Rules
```
optimization.sample_rate(byteOrString, rateNumerator, rateDenominator)

```
#### Description
This function determines whether to include an event based on a deterministic sampling strategy. This function returns:   `true` for a fraction of input values, equivalent to (`rateNumerator` / `rateDenominator`), indicating that the event should be included in the sample. `false` indicating that the event shouldn't be included in the sample.
This function is useful for optimization scenarios where you want to process only a subset of events. Equivalent to:
```
hash.fingerprint2011(byteOrString) % rateDenominator < rateNumerator

```
#### Param data types
byteOrString: Expression that evaluates to either a `BYTE` or `STRING`. rateNumerator: 'INT' rateDenominator: 'INT'
#### Return type
`BOOL`
#### Code sample
```
events:
    $e.metadata.event_type = "NETWORK_CONNECTION"
    $asset_id = $e.principal.asset.asset_id
    optimization.sample_rate($e.metadata.id, 1, 5) // Only 1 out of every 5 events

  match:
    $asset_id over 1h

  outcome:
    $event_count = count_distinct($e.metadata.id)
  // estimate the usage by multiplying by the inverse of the sample rate
    $usage_past_hour = sum(5.0 * $e.network.sent_bytes)

 condition:
  // Requiring a certain number of events after sampling avoids bias (e.g. a
  // device with just 1 connection will still show up 20% of the time and
  // if we multiply that traffic by 5, we'll get an incorrect estimate)
  $e and ($usage_past_hour > 1000000000) and $event_count >= 100

```
.supported-container { display: flex; gap: 7px; }
### strings.base64_decode
Supported in:    Rules   Search
```
strings.base64_decode(encodedString)

```
#### Description
Returns a string containing the base64 decoded version of the encoded string.
This function takes one base64 encoded string as an argument. If `encodedString` is not a valid base64 encoded string, the function returns `encodedString` unchanged.
#### Param data types
`STRING`
#### Return type
`STRING`
#### Code samples
##### Example 1
```
"test" = strings.base64_decode($e.principal.domain.name)

```
.supported-container { display: flex; gap: 7px; }
### strings.coalesce
Supported in:    Rules   Search
```
strings.coalesce(a, b, c, ...)

```
#### Description
This function takes an unlimited number of arguments and returns the value of the first expression that does not evaluate to an empty string (for example, "non-zero value"). If all arguments evaluate to an empty string, the function call returns an empty string.
The arguments can be literals, event fields, or function calls. All arguments must be of `STRING` type. If any arguments are event fields, the attributes must be from the same event.
#### Param data types
`STRING`
#### Return type
`STRING`
#### Code samples
##### Example 1
The following example includes string variables as arguments. The condition evaluates to true when (1) `$e.network.email.from` is `suspicious@gmail.com` or (2) `$e.network.email.from` is empty and `$e.network.email.to` is `suspicious@gmail.com`.
```
"suspicious@gmail.com" = strings.coalesce($e.network.email.from, $e.network.email.to)

```
##### Example 2
The following example calls the `coalesce` function with more than two arguments. This condition compares the first non-null IP address from event `$e` against values in the reference list `ip_watchlist`. The order that the arguments are coalesced in this call is the same as the order they are enumerated in the rule condition:  `$e.principal.ip` is evaluated first. `$e.src.ip` is evaluated next. `$e.target.ip` is evaluated next. Finally, the string "No IP" is returned as a default value if the previous `ip` fields are unset.
```
strings.coalesce($e.principal.ip, $e.src.ip, $e.target.ip, "No IP") in %ip_watchlist

```
##### Example 3
The following example attempts to coalesce `principal.hostname` from event `$e1` and event `$e2`. It will return a compiler error because the arguments are different event variables.
```
// returns a compiler error
"test" = strings.coalesce($e1.principal.hostname, $e2.principal.hostname)

```
.supported-container { display: flex; gap: 7px; }
### strings.concat
Supported in:    Rules   Search
```
strings.concat(a, b, c, ...)

```
#### Description
Returns the concatenation of an unlimited number of items, each of which can be a string, integer, or float.
If any arguments are event fields, the attributes must be from the same event.
#### Param data types
`STRING`, `FLOAT`, `INT`
#### Return type
`STRING`
#### Code samples
##### Example 1
The following example includes a string variable and integer variable as arguments. Both `principal.hostname` and `principal.port` are from the same event, `$e`, and are concatenated to return a string.
```
"google:80" = strings.concat($e.principal.hostname, ":", $e.principal.port)

```
##### Example 2
The following example includes a string variable and string literal as arguments.
```
"google-test" = strings.concat($e.principal.hostname, "-test") // Matches the event when $e.principal.hostname = "google"

```
##### Example 3
The following example includes a string variable and float literal as arguments. When represented as strings, floats that are whole numbers are formatted without the decimal point (for example, 1.0 is represented as "1"). Additionally, floats that exceed sixteen decimal digits are truncated to the sixteenth decimal place.
```
"google2.5" = strings.concat($e.principal.hostname, 2.5)

```
##### Example 4
The following example includes a string variable, string literal, integer variable, and float literal as arguments. All variables are from the same event, `$e`, and are concatenated with the literals to return a string.
```
"google-test802.5" = strings.concat($e.principal.hostname, "-test", $e.principal.port, 2.5)

```
##### Example 5
The following example attempts to concatenate principal.port from event `$e1`, with `principal.hostname` from event `$e2`. It will return a compiler error because the arguments are different event variables.
```
// Will not compile
"test" = strings.concat($e1.principal.port, $e2.principal.hostname)

```
.supported-container { display: flex; gap: 7px; }
### strings.contains
Supported in:    Rules   Search
```
strings.contains( str, substr )

```
#### Description
Returns true if a given string contains the specified substring. Otherwise it returns false.
#### Param data types
`STRING`, `STRING`
#### Return type
`BOOL`
#### Code samples
##### Example 1
This example returns true because the string has a substring "is".
```
strings.contains("thisisastring", "is") = true

```
##### Example 2
This example returns false because the string does not have substring "that".
```
strings.contains("thisisastring", "that") = false

```
.supported-container { display: flex; gap: 7px; }
### strings.count_substrings
Supported in:    Rules   Search
```
strings.count_substrings(string_to_search_in, substring_to_count)

```
#### Description
When given a string and a substring, returns an int64 of the count of non-overlapping occurrences of the substring within the string.
#### Param data types
`STRING`, `STRING`
#### Return type
`INT`
#### Code samples
This section contains examples that calculate the number of times a substring appears in a given string.
##### Example 1
This example uses a non-null string and a non-null single substring character.
```
strings.count_substrings("this`string`has`four`backticks", "`") = 4

```
##### Example 2
This example uses a non-null string and a non-null substring greater than one character.
```
strings.count_substrings("str", "str") = 1

```
##### Example 3
This example uses a non-null string and an empty substring.
```
strings.count_substrings("str", "") = 0

```
##### Example 4
This example uses an empty string and a non-null substring greater than one character.
```
strings.count_substrings("", "str") = 0

```
##### Example 5
This example uses an empty string and an empty substring.
```
strings.count_substrings("", "") = 0

```
##### Example 6
This example uses a non-null string and a non-null substring that is greater than one character and greater than one occurrence.
```
strings.count_substrings("fooABAbarABAbazABA", "AB") = 3

```
##### Example 7
This example uses a non-null string and a non-null substring that is greater than one character and greater than one occurrence. It highlights the limitation with overlapping substring occurrences
```
strings.count_substrings("ABABABA", "ABA") = 2

```
.supported-container { display: flex; gap: 7px; }
### strings.starts_with
Supported in:    Rules   Search
```
strings.starts_with(value, suffix)

```
#### Description
Function takes two strings `(value, suffix)`. Returns true if the suffix is non-empty and at start-of-value.
#### Param data types
`STRING`, `STRING`
#### Return type
`BOOL`
#### Code samples
The following code samples illustrate some of the ways you might use the `strings.starts_with` function.
##### Example: returns true
Returns true when the prefix is found at start-of-value.
```
strings.starts_with(target.hostname, "www") = true

```
##### Example: returns false
Returns false when the prefix isn't at start-of-value.
```
strings.starts_with(target.hostname, "www") = false

```
##### Example: returns true when identical
Returns true when prefix and value are identical.
```
target.hostname != "example.com"
strings.starts_with("str", "str") = true

```
##### Example: returns false when suffix empty
Returns false when prefix is an empty string.
```
target.hostname != "example.com"
strings.starts_with("", "str") = false

```
##### Example: returns false when value empty
Returns false when value is an empty string.
```
target.hostname != "example.com"
strings.starts_with("str", "") = false

```
##### Example: returns false when prefix and value are empty
Returns false when prefix and value are empty strings.
```
target.hostname != "example.com"
strings.starts_with("", "") = false

```
.supported-container { display: flex; gap: 7px; }
### strings.ends_with
Supported in:    Rules   Search
```
strings.ends_with(value, suffix)

```
#### Description
Function takes two strings `(value, suffix)`. Returns true if the suffix is non-empty and at end-of-value.
#### Param data types
`STRING`, `STRING`
#### Return type
`BOOL`
#### Code samples
The following code samples illustrate some of the ways you might use the `strings.ends_with` function.
##### Example: returns true
Returns true when the suffix is found at end-of-value.
```
strings.ends_with(target.hostname, "com") = true

```
##### Example: returns false
Returns false when the suffix isn't at end-of-value.
```
strings.ends_with(target.hostname, "com") = false

```
##### Example: returns false when identical
Returns false when suffix and value are identical.
```
target.hostname != "example.com"
strings.ends_with("str", "str") = true

```
##### Example: returns false when suffix empty
Returns false when suffix is an empty string.
```
target.hostname != "example.com"
strings.ends_with("str", "") = false

```
##### Example: returns false when value empty
Returns false when value is an empty string.
```
target.hostname != "example.com"
strings.ends_with("", "str") = false

```
##### Example: returns false when suffix and value are empty
Returns false when suffix and value are empty strings.
```
target.hostname != "example.com"
strings.ends_with("", "") = false

```
.supported-container { display: flex; gap: 7px; }
### strings.extract_domain
Supported in:    Rules   Search
```
strings.extract_domain(url_string)

```
#### Description
Extracts the domain from a string. Note: The function does not perform Unicode normalization.Note: The public suffix data at publicsuffix.org also contains private domains. This function does not treat a private domain as a public suffix. For example, if us.com is a private domain in the public suffix data, ("foo.us.com") returns us.com (the public suffix com plus the preceding label us) rather than foo.us.com (the private domain us.com plus the preceding label foo).Note: The public suffix data might change over time. Consequently, input that produces default empty value now may produce a non-empty value in the future.
#### Param data types
`STRING`
#### Return type
`STRING`
#### Code samples
##### Example 1
This example shows an empty string
```
strings.extract_domain("") = ""

```
##### Example 2
random string, not a URL
```
strings.extract_domain("1234") = ""

```
##### Example 3
multiple backslaches
```
strings.extract_domain("\\\\") = ""

```
##### Example 4
non-alphabet characters handled gracefully
```
strings.extract_domain("http://例子.卷筒纸.中国") = "卷筒纸.中国"

```
##### Example 5
handling URIs
```
strings.extract_domain("mailto:?to=&subject=&body=") = ""

```
##### Example 6
multiple characters before actual URL
```
strings.extract_domain("     \t   !$5*^)&dahgsdfs;http://www.google.com") = "google.com"

```
##### Example 7
special characters in URI `#`
```
strings.extract_domain("test#@google.com") = ""

```
##### Example 8
special characters in URL `#`
```
strings.extract_domain("https://test#@google.com") = ""

```
##### Example 9
positive test case
```
strings.extract_domain("https://google.co.in") = "google.co.in"

```
.supported-container { display: flex; gap: 7px; }
### strings.extract_hostname
Supported in:    Rules   Search
```
strings.extract_hostname(string)

```
#### Description
Extracts the hostname from a string. This function is case sensitive.
#### Param data types
`STRING`
#### Return type
`STRING`
#### Code samples
##### Example 1
This example returns an empty string.
```
strings.extract_hostname("") = ""

```
##### Example 2
random string, not a URL
```
strings.extract_hostname("1234") = "1234"

```
##### Example 3
multiple backslashes
```
strings.extract_hostname("\\\\") = ""

```
##### Example 4
non-English characters handled gracefully
```
strings.extract_hostname("http://例子.卷筒纸.中国") = "例子.卷筒纸.中国"

```
##### Example 5
handling URIs
```
strings.extract_hostname("mailto:?to=&subject=&body=") = "mailto"

```
##### Example 6
multiple characters before actual URL
```
strings.extract_hostname("     \t   !$5*^)&dahgsdfs;http://www.google.com") = "www.google.com"

```
##### Example 7
special characters in URI `#`
```
strings.extract_hostname("test#@google.com") = "test"

```
##### Example 8
special characters in URL `#`
```
strings.extract_hostname("https://test#@google.com") = "test"

```
.supported-container { display: flex; gap: 7px; }
### strings.from_base64
Supported in:    Rules   Search
```
strings.from_base64(base64_encoded_string)

```
#### Description
Function converts a base64 encoded `STRING` value to a raw binary `BYTES` value. Function calls with values that cannot be casted return an empty `BYTES` by default.
#### Param data types
`STRING`
#### Return type
`BYTES`
#### Code samples
##### Base64 Encoded String to Bytes Conversion
The function converts a base64 encoded string to its raw binary bytes representation.
```
strings.from_base64("AAAAAG+OxVhtAm+d2sVuny/hW4oAAAAAAQAAAM0AAAA=") = b'000000006f8ec5586d026f9ddac56e9f2fe15b8a0000000001000000cd000000

```
##### Failed Conversion (Defaults to Empty Bytes)
The function defaults to empty bytes if the provided value in invalid.
```
strings.from_base64("invalid-value") = b'

```
.supported-container { display: flex; gap: 7px; }
### strings.from_hex
Supported in:    Rules   Search
```
strings.from_hex(hex_string)

```
#### Description
Returns the bytes associated with the given hex string.
#### Param data types
`STRING`
#### Return type
`BYTES`
#### Code samples
Get bytes associated with a given hex string.
##### Example 1
This example shows non-hex character conversions.
```
strings.from_hex("str") // returns empty bytes

```
##### Example 2
This example shows input with empty string.
```
strings.from_hex("") // returns empty bytes

```
##### Example 3
This example shows hex string conversion.
```
strings.from_hex("1234") // returns 1234 bytes

```
##### Example 4
This example shows non-ASCII characters conversion.
```
strings.from_hex("筒纸.中国") // returns empty bytes

```
.supported-container { display: flex; gap: 7px; }
### strings.ltrim
Supported in:    Rules   Search
```
strings.ltrim(string_to_trim, cutset)

```
#### Description
Trims leading white spaces from a given string. This function removes leading characters present in that cutset.
#### Param data types
`STRING`, `STRING`
#### Return type
`STRING`
#### Code samples
The following are example use cases.
##### Example 1
This example uses the same first and second argument.
```
strings.ltrim("str", "str") = ""

```
##### Example 2
This example uses an empty string as the second argument.
```
strings.ltrim("str", "") = "str"

```
##### Example 3
This example uses an empty string as the first argument, and a string as the second argument.
```
strings.ltrim("", "str") = ""

```
##### Example 4
This example uses strings that contain white spaces, and a string as the second argument.
```
strings.ltrim("a aastraa aa ", " a") = "straa aa "

```
.supported-container { display: flex; gap: 7px; }
### strings.reverse
Supported in:    Rules   Search
```
strings.reverse(STRING)

```
#### Description
Returns a string that is the reverse of the input string.
#### Param data types
`STRING`
#### Return type
`STRING`
#### Code samples
##### Example 1
The following example passes a short string.
```
strings.reverse("str") = "rts"  // The function returns 'rts'.

```
##### Example 2
The following example passes an empty string.
```
strings.reverse("") = ""

```
##### Example 3
The following example passes a palindrome.
```
strings.reverse("tacocat") = "tacocat"

```
.supported-container { display: flex; gap: 7px; }
### strings.rtrim
Supported in:    Rules   Search
```
strings.rtrim(string_to_trim, cutset)

```
#### Description
Trims trailing white spaces from a given string. Removes trailing characters that are present in that cutset.
#### Param data types
`STRING`, `STRING`
#### Return type
`STRING`
#### Code samples
The following are example use cases.
##### Example 1
The following example passes the same string as the first and second argument.
```
strings.rtrim("str", "str") = ""

```
##### Example 2
The following example passes an empty string as the second argument.
```
strings.rtrim("str", "") = "str"

```
##### Example 3
The following example passes an empty string as the first argument and a non-empty string as the second argument.
```
strings.rtrim("", "str") = ""

```
##### Example 4
The following example passes a string containing white spaces as the first argument and a non-empty string as the second argument.
```
strings.rtrim("a aastraa aa ", " a") = "a aasstr"

```
.supported-container { display: flex; gap: 7px; }
### strings.split
Supported in:    Rules   Search
```
strings.split(string, delimiter)

```
#### Description
Splits string value using the delimiter argument. The default delimiter is a comma (`,`).
#### Param data types
`STRING`, `STRING`
#### Return type
`ARRAY_STRINGS`
#### Code samples
The following code samples illustrate some of the ways you might use the `strings.split` function.
##### Example: split string with default
The following example splits the string using the default delimiter, which is a comma.
```
strings.split("a,b,c,d") = ["a", "b", "c", "d"]

```
##### Example: split string with colon
The following example splits the string at each colon (`:`).
```
strings.split("a:b:c:d", ":") = ["a", "b", "c", "d"]

```
##### Example: missing delimiter
The following example is missing the delimiter in the string value.
```
strings.split("a,b,c,d", ":") = ["a,b,c,d"]

```
##### Example: empty delimiter
The following example has an empty delimiter string.
```
strings.split("abc", "") = ["a", "b", "c"]

```
.supported-container { display: flex; gap: 7px; }
### strings.to_lower
Supported in:    Rules   Search
```
strings.to_lower(stringText)

```
#### Description
This function takes an input string and returns a string after changing all characters to lowercase
#### Param data types
`STRING`
#### Return type
`STRING`
#### Code samples
##### Example 1
The following example returns `true`.
```
"test@google.com" = strings.to_lower($e.network.email.to)

```
.supported-container { display: flex; gap: 7px; }
### strings.to_upper
Supported in:    Rules   Search
```
strings.to_upper(string_val)

```
#### Description
Returns the original string with all alphabetic characters in uppercase.
#### Param data types
`STRING`
#### Return type
`STRING`
#### Code samples
##### Example 1
The following example returns the supplied argument in uppercase.
```
strings.to_upper("example") = "EXAMPLE"

```
.supported-container { display: flex; gap: 7px; }
### strings.trim
Supported in:    Rules   Search
```
strings.trim(string_to_trim, cutset)

```
#### Description
Trims leading and trailing white spaces from a given string. Also, remove unwanted characters (specified by the cutset argument) from the input string.
#### Param data types
`STRING`, `STRING`
#### Return type
`STRING`
#### Code samples
The following are example use cases.
##### Example 1
In the following example, the same string is passed as the input string and the cutset, which results in an empty string.
```
strings.trim("str", "str") // ""

```
##### Example 2
In the following example, an empty string is passed as the cutset, which results in the original string str because there are no characters specified in the cutset to remove.
```
strings.trim("str", "") = "str"

```
##### Example 3
In the following example, the function yields an empty string because the input string is already empty and there are no characters to remove.
```
strings.trim("", "str") = ""

```
##### Example 4
In the following example, the function yields str because the trim function removes the following:  trailing whitespace in "a aastraa aa " the characters specified in the cutset (space, a)
```
strings.trim("a aastraa aa ", " a") = "str"

```
.supported-container { display: flex; gap: 7px; }
### strings.url_decode
Supported in:    Rules   Search
```
strings.url_decode(url_string)

```
#### Description
Given a URL string, decode the escape characters and handle UTF-8 characters that have been encoded. Returns empty string if decoding fails.
#### Param data types
`STRING`
#### Return type
`STRING`
#### Code samples
##### Example 1
This example shows a positive test case.
```
strings.url_decode("three%20nine%20four") = "three nine four"

```
##### Example 2
This example shows an empty string case.
```
strings.url_decode("") // ""

```
##### Example 3
This example shows non-alphabet characters handling.
```
strings.url_decode("%E4%B8%8A%E6%B5%B7%2B%E4%B8%AD%E5%9C%8B") // "上海+中國"

```
##### Example 4
This example shows a sample URL decoding.
```
strings.url_decode("http://www.google.com%3Fparam1%3D%22+1+%3E+2+%22%26param2%3D2%3B") // 'http://www.google.com?param1="+1+>+2+"&param2=2;'

```
.supported-container { display: flex; gap: 7px; }
### timestamp.as_unix_seconds
Supported in:    Rules   Search
```
timestamp.as_unix_seconds(timestamp [, time_zone])

```
#### Description
This function returns an integer representing the number of seconds past a Unix epoch for the given timestamp string.  `timestamp` is a string representing a valid epoch timestamp. The format needs to be `%F %T`. `time_zone` is optional and is a string representing a time zone. If omitted, the default is `GMT`. You can specify time zones using string literals. The options are as follows:  The TZ database name, for example `America/Los_Angeles`. For more information, see the list of tz database time zones on Wikipedia. The time zone offset from UTC, in the format`(+|-)H[H][:M[M]]`, for example: "-08:00".
Here are examples of valid `time_zone` specifiers, which you can pass as the second argument to time extraction functions:
```
"America/Los_Angeles", or "-08:00". ("PST" is not supported)
"America/New_York", or "-05:00". ("EST" is not supported)
"Europe/London"
"UTC"
"GMT"

```
#### Param data types
`STRING`, `STRING`
#### Return type
`INT`
#### Code samples
##### Example 1
Valid epoch timestamp
```
timestamp.as_unix_seconds("2024-02-22 10:43:00") = 1708598580

```
##### Example 2
Valid epoch timestamp with the America/New_York time zone
```
timestamp.as_unix_seconds("2024-02-22 10:43:00", "America/New_York") = 1708616580

```
.supported-container { display: flex; gap: 7px; }
### timestamp.current_seconds
Supported in:    Rules   Search
```
timestamp.current_seconds()

```
#### Description
Returns an integer representing the current time in Unix seconds. This is approximately equal to the detection timestamp and is based on when the rule is run. This function is a synonym of the function `timestamp.now()`.
#### Param data types
`NONE`
#### Return type
`INT`
#### Code samples
##### Example 1
The following example returns `true` if the certificate has been expired for more than 24 hours. It calculates the time difference by subtracting the current Unix seconds, and then comparing using a greater than operator.
```
86400 < timestamp.current_seconds() - $e.network.tls.certificate.not_after

```
.supported-container { display: flex; gap: 7px; }
### timestamp.get_date
Supported in:    Rules   Search
```
timestamp.get_date(unix_seconds [, time_zone])

```
#### Description
This function returns a string in the format `YYYY-MM-DD`, representing the day a timestamp is in.  `unix_seconds` is an integer representing the number of seconds past Unix epoch, such as `$e.metadata.event_timestamp.seconds`, or a placeholder containing that value. `time_zone` is optional and is a string representing a time_zone. If omitted, the default is "GMT". You can specify time zones using string literals. The options are:  The TZ database name, for example "America/Los_Angeles". For more information, see the "TZ Database Name" column from this page  The time zone offset from UTC, in the format`(+|-)H[H][:M[M]]`, for example: "-08:00".
Here are examples of valid time_zone specifiers, which you can pass as the second argument to time extraction functions:
```
"America/Los_Angeles", or "-08:00". ("PST" is not supported)
"America/New_York", or "-05:00". ("EST" is not supported)
"Europe/London"
"UTC"
"GMT"

```
#### Param data types
`INT`, `STRING`
#### Return type
`STRING`
#### Code samples
##### Example 1
In this example, the `time_zone` argument is omitted, so it defaults to "GMT".
```
$ts = $e.metadata.collected_timestamp.seconds

timestamp.get_date($ts) = "2024-02-19"

```
##### Example 2
This example uses a string literal to define the `time_zone`.
```
$ts = $e.metadata.collected_timestamp.seconds

timestamp.get_date($ts, "America/Los_Angeles") = "2024-02-20"

```
.supported-container { display: flex; gap: 7px; }
### timestamp.get_minute
Supported in:    Rules   Search
```
timestamp.get_minute(unix_seconds [, time_zone])

```
#### Description
This function returns an integer in the range `[0, 59]` representing the minute.  `unix_seconds` is an integer representing the number of seconds past Unix epoch, such as `$e.metadata.event_timestamp.seconds`, or a placeholder containing that value. `time_zone` is optional and is a string representing a time zone. If omitted, the default is "GMT". You can specify time zones using string literals. The options are:  The TZ database name, for example "America/Los_Angeles". For more information, see the "TZ Database Name" column from this page  The time zone offset from UTC, in the format`(+|-)H[H][:M[M]]`, for example: "-08:00".
Here are examples of valid `time_zone` specifiers, which you can pass as the second argument to time extraction functions:
```
"America/Los_Angeles", or "-08:00". ("PST" is not supported)
"America/New_York", or "-05:00". ("EST" is not supported)
"Europe/London"
"UTC"
"GMT"

```
#### Param data types
`INT`, `STRING`
#### Return type
`INT`
#### Code samples
##### Example 1
In this example, the `time_zone` argument is omitted, so it defaults to "GMT".
```
$ts = $e.metadata.collected_timestamp.seconds

timestamp.get_hour($ts) = 15

```
##### Example 2
This example uses a string literal to define the `time_zone`.
```
$ts = $e.metadata.collected_timestamp.seconds

timestamp.get_hour($ts, "America/Los_Angeles") = 15

```
.supported-container { display: flex; gap: 7px; }
### timestamp.get_hour
Supported in:    Rules   Search
```
timestamp.get_hour(unix_seconds [, time_zone])

```
#### Description
This function returns an integer in the range `[0, 23]` representing the hour.  `unix_seconds` is an integer representing the number of seconds past Unix epoch, such as `$e.metadata.event_timestamp.seconds`, or a placeholder containing that value. `time_zone` is optional and is a string representing a time zone. If omitted, the default is "GMT". You can specify time zones using string literals. The options are:  The TZ database name, for example "America/Los_Angeles". For more information, see the "TZ Database Name" column from this page  The time zone offset from UTC, in the format`(+|-)H[H][:M[M]]`, for example: "-08:00".
Here are examples of valid `time_zone` specifiers, which you can pass as the second argument to time extraction functions:
```
"America/Los_Angeles", or "-08:00". ("PST" is not supported)
"America/New_York", or "-05:00". ("EST" is not supported)
"Europe/London"
"UTC"
"GMT"

```
#### Param data types
`INT`, `STRING`
#### Return type
`INT`
#### Code samples
##### Example 1
In this example, the `time_zone` argument is omitted, so it defaults to "GMT".
```
$ts = $e.metadata.collected_timestamp.seconds

timestamp.get_hour($ts) = 15

```
##### Example 2
This example uses a string literal to define the `time_zone`.
```
$ts = $e.metadata.collected_timestamp.seconds

timestamp.get_hour($ts, "America/Los_Angeles") = 15

```
.supported-container { display: flex; gap: 7px; }
### timestamp.get_day_of_week
Supported in:    Rules   Search
```
timestamp.get_day_of_week(unix_seconds [, time_zone])

```
#### Description
This function returns an integer in the range `[1, 7]` representing the day of week starting with Sunday. For example, 1 = Sunday and 2 = Monday.  `unix_seconds` is an integer representing the number of seconds past Unix epoch, such as `$e.metadata.event_timestamp.seconds`, or a placeholder containing that value. `time_zone` is optional and is a string representing a time_zone. If omitted, the default is "GMT". You can specify time zones using string literals. The options are:  The TZ database name, for example "America/Los_Angeles". For more information, see the "TZ Database Name" column from this page  The time zone offset from UTC, in the format`(+|-)H[H][:M[M]]`, for example: "-08:00".
Here are examples of valid time_zone specifiers, which you can pass as the second argument to time extraction functions:
```
"America/Los_Angeles", or "-08:00". ("PST" is not supported)
"America/New_York", or "-05:00". ("EST" is not supported)
"Europe/London"
"UTC"
"GMT"

```
#### Param data types
`INT`, `STRING`
#### Return type
`INT`
#### Code samples
##### Example 1
In this example, the `time_zone` argument is omitted, so it defaults to "GMT".
```
$ts = $e.metadata.collected_timestamp.seconds

timestamp.get_day_of_week($ts) = 6

```
##### Example 2
This example uses a string literal to define the `time_zone`.
```
$ts = $e.metadata.collected_timestamp.seconds

timestamp.get_day_of_week($ts, "America/Los_Angeles") = 6

```
.supported-container { display: flex; gap: 7px; }
### timestamp.get_timestamp
Supported in:    Rules   Search
```
timestamp.get_timestamp(unix_seconds, optional timestamp_format/time_granularity, optional timezone)

```
#### Description
This function returns a string in the format `YYYY-MM-DD`, representing the day a timestamp is in.  `unix_seconds` is an integer representing the number of seconds past Unix epoch, such as `$e.metadata.event_timestamp.seconds`, or a placeholder containing that value. `timestamp_format` is optional and is a string representing the format for the timestamp. If omitted, the default is `%F %T`. You can specify the format using a date time format string or one of the following time granularity: `SECOND`, `MINUTE`, `HOUR`, `DATE`, `WEEK`, `MONTH`, or `YEAR`. For more formatting options, see Format elements for date and time parts `time_zone` is optional and is a string representing a time zone. If omitted, the default is `GMT`. You can specify time zones using string literals. The options are as follows:  The IANA Time Zone (TZ) database name, for example, `America/Los_Angeles`. For more information, see the list of tz database time zones on Wikipedia. The time zone offset from UTC, in the format `(+|-)H[H][:M[M]]`, for example: "-08:00".   Note: To maintain consistency with standard Gregorian calendar years, always use the 4-digit %Y format. Avoid using %y (2-digit) to prevent sorting errors, and avoid %G (ISO year), which can shift dates near the New Year depending on the week cycle.
Here are examples of valid `time_zone` specifiers, which you can pass as the second argument to time extraction functions:
```
"America/Los_Angeles", or "-08:00". ("PST" is not supported)
"America/New_York", or "-05:00". ("EST" is not supported)
"Europe/London"
"UTC"
"GMT"

```
#### Param data types
`INT`, `STRING`, `STRING`
#### Return type
`STRING`
#### Code samples
##### Example 1
In this example, the `time_zone` argument is omitted, so it defaults to `GMT`.
```
$ts = $e.metadata.collected_timestamp.seconds

timestamp.get_timestamp($ts) = "2024-02-22 10:43:51"

```
##### Example 2
This example uses a string literal to define the `time_zone`.
```
$ts = $e.metadata.collected_timestamp.seconds

timestamp.get_timestamp($ts, "%F %T", "America/Los_Angeles") = "2024-02-22 10:43:51"

```
##### Example 3
This example uses a string literal to define the `timestamp_format`.
```
$ts = $e.metadata.collected_timestamp.seconds

timestamp.get_timestamp($ts, "%Y-%m", "GMT") = "2024-02"

```
##### Example 4
This example formats a unix timestamp as a string at second granularity.
```
timestamp.get_timestamp(1708598631, "SECOND", "GMT") = "2024-02-22 10:43:51"

```
##### Example 5
This example formats a unix timestamp as a string at minute granularity.
```
timestamp.get_timestamp(1708598631, "MINUTE", "GMT") = "2024-02-22 10:43"

```
##### Example 6
This example formats a unix timestamp as a string at hour granularity.
```
timestamp.get_timestamp(1708598631, "HOUR", "GMT") = "2024-02-22 10"

```
##### Example 7
This example formats a unix timestamp as a string at day granularity.
```
timestamp.get_timestamp(1708598631, "DATE", "GMT") = "2024-02-22"

```
##### Example 8
This example formats a unix timestamp as a string at week granularity.
```
timestamp.get_timestamp(1708598631, "WEEK", "GMT") = "2024-02-18"

```
##### Example 9
This example formats a unix timestamp as a string at month granularity.
```
timestamp.get_timestamp(1708598631, "MONTH", "GMT") = "2024-02"

```
##### Example 10
This example formats a unix timestamp as a string at year granularity.
```
timestamp.get_timestamp(1708598631, "YEAR", "GMT") = "2024"

```
.supported-container { display: flex; gap: 7px; }
### timestamp.get_week
Supported in:    Rules   Search
```
timestamp.get_week(unix_seconds [, time_zone])

```
#### Description
This function returns an integer in the range `[0, 53]` representing the week of the year. Weeks begin with Sunday. Dates before the first Sunday of the year are in week 0.  `unix_seconds` is an integer representing the number of seconds past Unix epoch, such as `$e.metadata.event_timestamp.seconds`, or a placeholder containing that value. `time_zone` is optional and is a string representing a time zone. If omitted, the default is "GMT". You can specify time zones using string literals. The options are:  The TZ database name, for example "America/Los_Angeles". For more information, see the "TZ Database Name" column from this page  The time zone offset from UTC, in the format`(+|-)H[H][:M[M]]`, for example: "-08:00".
Here are examples of valid `time_zone` specifiers, which you can pass as the second argument to time extraction functions:
```
"America/Los_Angeles", or "-08:00". ("PST" is not supported)
"America/New_York", or "-05:00". ("EST" is not supported)
"Europe/London"
"UTC"
"GMT"

```
#### Param data types
`INT`, `STRING`
#### Return type
`INT`
#### Code samples
##### Example 1
In this example, the `time_zone` argument is omitted, so it defaults to "GMT".
```
$ts = $e.metadata.collected_timestamp.seconds

timestamp.get_week($ts) = 0

```
##### Example 2
This example uses a string literal to define the `time_zone`.
```
$ts = $e.metadata.collected_timestamp.seconds

timestamp.get_week($ts, "America/Los_Angeles") = 0

```
.supported-container { display: flex; gap: 7px; }
### timestamp.now
Supported in:    Rules   Search
```
timestamp.now()

```
#### Description
Returns the number of seconds since 1970-01-01 00:00:00 UTC. This is also known as Unix epoch time.
#### Return type
`INT`
#### Code samples
##### Example 1
The following example returns a timestamp for code executed on May 22, 2024 at 18:16:59.
```
timestamp.now() = 1716401819 // Unix epoch time in seconds for May 22, 2024 at 18:16:59

```
.supported-container { display: flex; gap: 7px; }
### window.avg
Supported in:    Rules
```
window.avg(numeric_values [, should_ignore_zero_values])

```
#### Description
Returns the average of the input values (which can be Integers or Floats). Setting the optional second argument to true ignores zero values.
#### Param data types
`INT|FLOAT`
#### Return type
`FLOAT`
#### Code samples
##### Example 1
This example shows the integer average.
```
// This rule sets the outcome $size_mode to the average
// file size in the 5 minute match window.
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $size_mode = window.avg($e.file.size) // yields 2.5 if the event file size values in the match window are 1, 2, 3 and 4

```
##### Example 2
This example shows the float average.
```
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $size_mode = window.avg($e.file.size) // yields 1.75 if the event file size values in the match window are 1.1 and 2.4

```
##### Example 3
Negative input average
```
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $size_mode = window.avg($e.file.size) // yields 0.6 if the event file size values in the match window are -1.1, 1.1, 0.0 and 2.4

```
##### Example 4
0 returns 0
```
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $size_mode = window.avg($e.file.size) // yields 0 if the event file size values in the match window is 0

```
##### Example 5
Ignoring 0 values
```
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $size_mode = window.avg($e.file.size, true) // yields 394 if the event file size values in the match window are 0, 0, 0 and 394

```
.supported-container { display: flex; gap: 7px; }
### window.first
Supported in:    Rules
```
window.first(values_to_sort_by, values_to_return)

```
#### Description
This aggregation function returns a string value derived from an event with the lowest correlated int value in the match window. An example use case is getting the userid from the event with the lowest timestamp in the match window (earliest event).
#### Param data types
`INT`, `STRING`
#### Return type
`STRING`
#### Code samples
Get a string value derived from an event with the lowest correlated int value in the match window.
```
// This rule sets the outcome $first_event to the lowest correlated int value
// in the 5 minute match window.
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $first_event = window.first($e.metadata.timestamp.seconds, $e.metadata.event_type) // yields v1 if the events in the match window are 1, 2 and 3 and corresponding values v1, v2, and v3.

```
.supported-container { display: flex; gap: 7px; }
### window.last
Supported in:    Rules
```
window.last(values_to_sort_by, values_to_return)

```
#### Description
This aggregation function returns a string value derived from an event with the highest correlated int value in the match window. An example use case is getting the userid from the event with the lowest timestamp in the match window (highest timestamp).
#### Param data types
`INT`, `STRING`
#### Return type
`STRING`
#### Code samples
Get a string value derived from an event with the highest correlated int value in the match window.
```
rule test_windows_last {

// This rule sets the outcome $last_event to the highest correlated int value
// in the 5 minute match window.

  meta:

  events:
    $e.principal.user.userid = $userid

  match:
    $userid over 5m

  outcome:
    $last_event = window.last($e.metadata.event_timestamp.seconds, 
    $e.metadata.vendor_name)
    // yields v3 if the events in the match window are 1, 2 and 3 and 
    // corresponding values v1, v2, and v3.

  condition:
    $e
}

```
.supported-container { display: flex; gap: 7px; }
### window.median
Supported in:    Rules
```
window.median(numeric_values, should_ignore_zero_values)

```
#### Description
Return the median of the input values. If there are 2 median values, only 1 will be non-deterministically chosen as the return value.
#### Param data types
`INT|FLOAT`, `BOOL`
#### Return type
`FLOAT`
#### Code samples
##### Example 1
This example returns the median when the input values aren't zero.
```
rule median_file_size {
    meta:
    events:
      $e.metadata.event_type = "FILE_COPY"
        $userid = $e.principal.user.userid
    match:
      $userid over 1h
    outcome:
      $median_file_size = window.median($e.principal.file.size) // returns 2 if the file sizes in the match window are [1, 2, 3]
  condition:
      $e
}

```
##### Example 2
This example returns the median when the input includes some zero values that shouldn't be ignored.
```
rule median_file_size {
    meta:
    events:
      $e.metadata.event_type = "FILE_COPY"
        $userid = $e.principal.user.userid
    match:
      $userid over 1h
    outcome:
      $median_file_size = window.median($e.principal.file.size) // returns 1 if the file sizes in the match window are [0,0, 1, 2, 3]
  condition:
      $e
}

```
##### Example 3
This example returns the median when the input includes some zero values which should be ignored.
```
rule median_file_size {
    meta:
    events:
      $e.metadata.event_type = "FILE_COPY"
        $userid = $e.principal.user.userid
    match:
      $userid over 1h
    outcome:
      $median_file_size = window.median($e.principal.file.size, true) // returns 2 if the file sizes in the match window are [0,0, 1, 2, 3]
  condition:
      $e
}

```
##### Example 4
This example returns the median when the input includes all zero values which should be ignored.
```
rule median_file_size {
    meta:
    events:
      $e.metadata.event_type = "FILE_COPY"
        $userid = $e.principal.user.userid
    match:
      $userid over 1h
    outcome:
      $median_file_size = window.median($e.principal.file.size) // returns 0 if the file sizes in the match window are [0,0]
  condition:
      $e
}

```
##### Example 5
This example shows that, when there are multiple medians, only one median is returned.
```
rule median_file_size {
    meta:
    events:
      $e.metadata.event_type = "FILE_COPY"
        $userid = $e.principal.user.userid
    match:
      $userid over 1h
    outcome:
      $median_file_size = window.median($e.principal.file.size) // returns 1 if the file sizes in the match window are [1, 2, 3, 4]
  condition:
      $e
}

```
.supported-container { display: flex; gap: 7px; }
### window.mode
Supported in:    Rules
```
window.mode(values)

```
#### Description
Return the mode of the input values. In case of multiple possible mode values, only one of those values will be non-deterministically chosen as the return value.
#### Param data types
`INT|FLOAT|STRING`
#### Return type
`STRING`
#### Code samples
##### Example 1
Get mode of the values in the match window.
```
// This rule sets the outcome $size_mode to the most frequently occurring
// file size in the 5 minute match window.
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $size_mode = window.mode($e.file.size) // yields 1.6 if the event file size values in the match window are 1.6, 2, and 1.6

```
.supported-container { display: flex; gap: 7px; }
### window.range
Supported in:    Rules   Search
```
window.range(numeric_values, optional should_ignore_zero_values)

```
#### Description
Returns the range of the values input values found (min, max inclusive). Each value can be an integer or a floating point. Setting the optional second argument to true ignores zero values.
#### Param data types
`INT|FLOAT`, `BOOL`
#### Return type
`ARRAY_FLOATS`
#### Code samples
The following code samples illustrate some of the ways you might use the `window.range` function.
##### Example: minimum and maximum integer
This example shows the minimum and maximum integer value.
```
window.range([1, 2, 3, 4], false) = [1.000000, 4.000000]

```
##### Example: minimum and maximum floating point
This example shows the minimum and maximum floating point value.
```
window.range([1.100000, 39.400000, 2.400000], false) = [1.100000, 39.400000]

```
##### Example: minimum and maximum negative integer
This example shows the minimum and maximum negative integer value.
```
window.range([-1.100000, 1.100000, 0.000000, 2.400000], false) = [-1.100000, 2.400000]

```
##### Example: ignored 0 value
This example shows how 0 values are ignored when you set the second parameter.
```
window.range([0, 0, 0, 394, 1], true) = [1.000000, 394.000000]

```
.supported-container { display: flex; gap: 7px; }
### window.stddev
Supported in:    Rules
```
window.stddev(numeric_values)

```
#### Description
Returns the standard deviation of input values in a match window.
#### Param data types
`INT|FLOAT`
#### Return type
`FLOAT`
#### Code samples
##### Example 1
This example returns the standard deviation of integers in a match window.
```
// This rule creates a detection when the file size stddev in 5 minutes for a user is over a threshold.
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $p1 = window.stddev($e.file.size) // yields 4.0 if the event file size values in the match window are [10, 14, 18].
condition:
  $e and #p1 > 2

```
##### Example 2
This example returns the standard deviation of floats in a match window.
```
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $p1 = window.stddev($e.file.size) // yields 4.488686 if the event file size values in the match window are [10.00, 14.80, 18.97].
condition:
  $e and #p1 > 2

```
##### Example 3
This example returns the standard deviation in a match window that contains negative numbers.
```
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $p1 = window.stddev($e.file.size) // yields 48.644972 if the event file size values in the match window are [-1, -56, -98].
condition:
  $e and #p1 > 2

```
##### Example 4
This example returns with zero standard deviation when all values in the match window are the same.
```
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $p1 = window.stddev($e.file.size) // yields 0.000000 if the event file size values in the match window are [1, 1, 1].
condition:
  $e and #p1 > 2

```
##### Example 5
This example returns the standard deviation of a match window containing positive and negative numbers.
```
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $p1 = window.stddev($e.file.size) // yields 1.000000 if the event file size values in the match window are [1, 0, -1].
condition:
  $e and #p1 > 10

```
.supported-container { display: flex; gap: 7px; }
### window.variance
Supported in:    Rules
```
window.variance(values)

```
#### Description
This function returns the specified variance of the input values.
#### Param data types
`INT|FLOAT`
#### Return type
`FLOAT`
#### Code samples
##### Example 1
This example returns the variance of all integers.
```
// This rule creates a detection when the file size variance in 5 minutes for a user is over a threshold.
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $p1 = window.variance($e.file.size) // yields 16 if the event file size values in the match window are [10, 14, 18].
condition:
  $e and #p1 > 10

```
##### Example 2
This example returns the variance of all floats.
```
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $p1 = window.variance($e.file.size) // yields 20.148300 if the event file size values in the match window are [10.00, 14.80, 18.97].
condition:
  $e and #p1 > 10

```
##### Example 3
This example returns the variance of negative numbers.
```
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $p1 = window.variance($e.file.size) // yields 2366.333333 if the event file size values in the match window are [-1, -56, -98].
condition:
  $e and #p1 > 10

```
##### Example 4
This example returns a small variance value.
```
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $p1 = window.variance($e.file.size) // yields 0.000000 if the event file size values in the match window are [0.000000, 0.000000, 0.000100].
condition:
  $e and #p1 > 10

```
##### Example 5
This example returns a zero variance.
```
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $p1 = window.variance($e.file.size) // yields 0.000000 if the event file size values in the match window are [1, 1, 1].
condition:
  $e and #p1 > 10

```
##### Example 6
This example returns the variance of positive and negative numbers.
```
events:
 $e.user.userid = $userid
match:
 $userid over 5m
outcome:
  $p1 = window.variance($e.file.size) // yields 1.000000 if the event file size values in the match window are [1, 0, -1].
condition:
  $e and #p1 > 10

```