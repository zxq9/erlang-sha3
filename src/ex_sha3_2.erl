-module(ex_sha3_2).

-compile(export_all).


shake128(Bytes, OutputLength) -> shake(Bytes, 128, OutputLength).

shake256(Bytes, OutputLength) -> shake(Bytes, 256, OutputLength).

shake(Bytes, Width, OutputLength) ->
    Capacity = Width * 2,
    BitRate = 1600 - Capacity,
    keccak(BitRate, Capacity, Bytes, 16#1F, OutputLength).


sha3_224(Bytes) -> sha3(Bytes, 224).

sha3_256(Bytes) -> sha3(Bytes, 256).

sha3_384(Bytes) -> sha3(Bytes, 384).

sha3_512(Bytes) -> sha3(Bytes, 512).

sha3(Bytes, BitWidth) ->
    ByteWidth = BitWidth div 8,
    Capacity = BitWidth * 2,
    BitRate = 1600 - Capacity,
    keccak(BitRate, Capacity, Bytes, 16#06, ByteWidth).


keccak(BitRate, Capacity, Input, Suffix, OutputLength) ->
    case BitRate + Capacity =:= 1600 andalso BitRate rem 8 =:= 0 of
        true  -> absorb(Input, BitRate, Suffix, OutputLength);
        false -> error
    end.

absorb(Input, BitRate, Suffix, OutLength) ->
    ByteRate    = BitRate div 8,
    Sponge      = <<0:ByteRate/binary>>,
    SoggySponge = absorb(Input, ByteRate, Sponge),
    squeeze(SoggySponge, ByteRate, OutLength).

absorb(<<Block:ByteRate/binary, Rest/binary>>, ByteRate, Suffix, Sponge) ->
    SoakedSponge = soak(Sponge, Block),
    KekkedSponge = keccakF1600(SoakedSponge),
    absorb(Rest, ByteRate, Suffix, KekkedSponge);
absorb(<<>>, ByteRate, Suffix, Sponge) ->
    pad(Sponge, 1, ByteRate, Suffix);
absorb(Block, ByteRate, Suffix, Sponge) ->
    Size = byte_size(Block),
    TailSize = ByteRate - Size,
    SoakedSponge = soak(Sponge, <<Block/binary, 0:TailSize>>),
    pad(SoakedSponge, Size, ByteRate, Suffix).

soak(<<SpongeByte, SpongeTail/binary>>, <<BlockByte, BlockTail/binary>>) ->
    <<(SpongeByte bxor BlockByte), (soak(SpongeTail, BlockTail))/binary>>;
soak(<<>>, <<>>) ->
    <<>>.

pad(SoakedSponge, Index, ByteRate, Suffix) when Index =:= byte_size(SoakedSponge) ->
    <<Head:(Index - 1)/binary, Byte:8, Tail/binary>> = SoakedSponge,
    PaddedByte = Byte bxor Suffix,
    SoggySponge = <<Head/binary, PaddedByte, Tail/binary>>,
    KekkedSponge =
        case (Suffix band 16#80 =/= 0) andalso (Index =:= ByteRate) of
            true  -> keccakF1600(SoggySponge);
            false -> SoggySponge
        end,
    {Head, <<Tail>>} = split_binary(KekkedSponge, byte_size(KekkedSponge)),
    keccak(<<Head/binary, (Tail bxor 16#80)>>).

squeeze(Sponge, Rate, OutLength) ->
    squeeze(Sponge, Rate, OutLength, <<>>).

squeeze(Sponge, Rate, OutLength, Squeezed) ->
    BlockSize = min(Rate, OutLength),
    squeeze().


keccakF1600(Sponge) ->
    J = lists:seq(0, 4),
    Lanes = [[load64(binary_part(Sponge, 8 * (X + 5 * Y), 8) || Y <- J] X <- J],
    FullyKekked = keccakf1600lanes(Lanes, 1, 24),

keccakf1600lanes(Lanes, R, Rounds) when Rounds >= 0 ->
    J = lists:seq(0, 4),
    BigD = reach_around([bxor_fold(Lane) || Lane <- Lanes]),
    Pozzed = pozz(Lanes, BigD),
    

bxor_fold(Nums) ->
    lists:foldl(fun(A, B) -> A bxor B end, 0, Nums).


reach_around([A, B, C, D, E]) ->
    lists:zipwith(fun jiggle/2, [E, A, B, C, D], [B, C, D, E, A]).

jiggle(A, B) ->
    A bxor rol64(B, 1).


pozz(Lanes, Ds) ->
    lists:zipwith(fun sfp/2, Lanes, Ds).


sfp(Lane, D) ->
    [N bxor D || N <- Lane].


rol64(A, N) ->
    ((A bsr (64 - (N rem 64))) + (A bsl (N rem 64))) rem (1 bsl 64).


load64(B) ->
    lists:sum([binary:at(B, I) bsl (8 * I) || I <- lists:seq(0, 7)]).


store64(N) ->
    [(N bsr (8 * I)) rem 256 || I <- lists:seq(0, 7)].
