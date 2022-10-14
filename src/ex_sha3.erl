-module(ex_sha3).

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
    Sponge      = lotta_zeroes(),
    SoggySponge = suck(Input, ByteRate, Suffix, Sponge),
    squeeze(SoggySponge, ByteRate, OutLength).

suck(Input, ByteRate, Suffix, Sponge) ->
    case Input of
        <<Block:ByteRate/binary, Rest/binary>> ->
            SoakedSponge = soak(Sponge, Block),
            KekkedSponge = keccakF1600(SoakedSponge),
            suck(Rest, ByteRate, Suffix, KekkedSponge);
        <<>> ->
            pad(Sponge, 1, ByteRate, Suffix);
        Block ->
            Size = byte_size(Block),
            SoakedSponge = soak(Sponge, Block),
            pad(SoakedSponge, Size, ByteRate, Suffix)
    end.

soak(<<SpongeByte:8, SpongeTail/binary>>, <<BlockByte:8, BlockTail/binary>>) ->
    <<(SpongeByte bxor BlockByte):8, (soak(SpongeTail, BlockTail))/binary>>;
soak(Sponge, <<>>) ->
    Sponge.

pad(SoakedSponge, Index, ByteRate, Suffix) ->
    <<Head:(Index - 1)/binary, Byte:8, Tail/binary>> = SoakedSponge,
    PaddedByte = Byte bxor Suffix,
    SoggySponge = <<Head/binary, PaddedByte, Tail/binary>>,
    KekkedSponge =
        case (Suffix band 16#80 =/= 0) andalso (Index =:= ByteRate) of
            true  -> keccakF1600(SoggySponge);
            false -> SoggySponge
        end,
    case split_binary(KekkedSponge, byte_size(KekkedSponge)) of
        {H, <<>>}  -> keccakF1600(H);
        {H, <<T>>} -> keccakF1600(<<H/binary, (T bxor 16#80)>>)
    end.

squeeze(Sponge, Rate, OutLength) ->
    squeeze(Sponge, Rate, OutLength, <<>>).

squeeze(Sponge, Rate, OutLength, Out) ->
    BlockSize = min(Rate, OutLength),
    NewOut = <<Out/binary, (binary_part(Sponge, 0, BlockSize))/binary>>,
    NewOutLength = OutLength - BlockSize,
    case NewOutLength > 0 of
        true ->
            Kekked = keccakF1600(Sponge),
            squeeze(Kekked, Rate, NewOutLength, NewOut);
        false ->
            NewOut
    end.


keccakF1600(Sponge) ->
    Q = lists:seq(0, 4),
    Lanes = [[load64(binary_part(Sponge, 8 * (X + 5 * Y), 8)) || Y <- Q] || X <- Q],
    FullyKekked = keccakF1600lanes(Lanes),
    EmptySponge = lotta_zeroes(),
    store(FullyKekked, EmptySponge).

store(FullyKekked, Sponge) ->
    Keks = list_to_tuple([list_to_tuple(K) || K <- FullyKekked]),
    store(Keks, Sponge, 0).

store(FullyKekked, Sponge, X) ->
    Loaded = store(FullyKekked, Sponge, X, 0),
    NewX = X + 1,
    case NewX < 5 of
        true  -> store(FullyKekked, Loaded, NewX);
        false -> Loaded
    end.

store(FullyKekked, Sponge, X, Y) ->
    Chunk = store64(element(Y + 1, element(X + 1, FullyKekked))),
    Index = 8 * (X + 5 * Y) + 1,
    <<Head:(Index - 1)/binary, _:8/binary, Tail/binary>> = Sponge,
    Stored = <<Head/binary, Chunk/binary, Tail/binary>>,
    NewY = Y + 1,
    case NewY < 5 of
        true  -> store(FullyKekked, Stored, X, NewY);
        false -> Stored
    end.

keccakF1600lanes(Lanes) ->
    keccakF1600lanes(Lanes, 0).

keccakF1600lanes(Lanes, Rounds) when Rounds < 24 ->
    BigD = reach_around([bxor_fold(Lane) || Lane <- Lanes]),
    DirtyLanes = little(xxx(pee_pie(pozz(Lanes, BigD)))),
    keccakF1600lanes(DirtyLanes, Rounds + 1);
keccakF1600lanes(Lanes, _) ->
    Lanes.
%   Pozzed = pozz(Lanes, BigD),
%   PeePie = pee_pie(Pozzed),
%   XXX = xxx(PeePie),
%   little(XXX).

reach_around([A, B, C, D, E]) ->
    lists:zipwith(fun jiggle/2, [E, A, B, C, D], [B, C, D, E, A]).

jiggle(A, B) ->
    A bxor rol64(B, 1).

bxor_fold(Nums) ->
    lists:foldl(fun(A, B) -> A bxor B end, 0, Nums).

pozz(Lanes, Ds) ->
    list_to_tuple(lists:zipwith(fun sfp/2, Lanes, Ds)).

sfp(Lane, D) ->
    list_to_tuple([N bxor D || N <- Lane]).

pee_pie(Pozzed) ->
    X = 2,
    Y = 1,
    Round = 0,
    pee_pie(Pozzed, X, Y, Round).

pee_pie(TLanes, X, Y, Round) ->
    Current = element(Y, element(X, TLanes)),
    NewX = Y,
    NewY = (((2 * X) + (3 * Y)) rem 5) + 1,
    Rolled = rol64(Current, ((Round + 1) * (Round + 2)) div 2),
    NewLanes = setelement(NewY, TLanes, setelement(NewX, element(NewY, TLanes), Rolled)),
    NewRound = Round + 1,
    case NewRound =< 24 of
        true  -> pee_pie(NewLanes, NewX, NewY, NewRound);
        false -> NewLanes
    end.

xxx(PeePie) ->
    xxx(PeePie, 1).

xxx(PeePie, Y) ->
    T = element(Y, PeePie),
    NewPeePie = xxx(PeePie, T, Y, 1),
    NewY = Y + 1,
    case NewY =< 5 of
        true  -> xxx(NewPeePie, NewY);
        false -> NewPeePie
    end.

xxx(PeePie, T, Y, X) ->
    T1 = element(((X + 1) rem 5) + 1, T),
    T2 = element(((X + 2) rem 5) + 1, T),
    NewPee = element(X, T) bxor (bnot T1 band T2),
    NewPeePie = setelement(Y, PeePie, setelement(X, element(Y, PeePie), NewPee)),
    NewX = X + 1,
    case NewX =< 5 of
        true  -> xxx(NewPeePie, T, Y, NewX);
        false -> NewPeePie
    end.

little(XXX) ->
    little(XXX, 1, 0).

little(XXX, R, J) when J < 7 ->
    NewR = ((R bsl 1) bxor ((R bsr 7) * 16#71)) rem 256,
    case NewR rem 2 of
        0 ->
            little(XXX, NewR, J + 1);
        1 ->
            S = element(1, element(1, XXX)),
            Magic = S bxor (1 bsl ((1 bsl J) - 1)),
            NewXXX = setelement(1, XXX, setelement(1, element(1, XXX), Magic)),
            little(NewXXX, NewR, J + 1)
    end;
little(XXX, _, _) ->
    [tuple_to_list(X) || X <- tuple_to_list(XXX)].


rol64(A, N) ->
    ((A bsr (64 - (N rem 64))) + (A bsl (N rem 64))) rem (1 bsl 64).


load64(B) ->
    lists:sum([binary:at(B, I) bsl (8 * I) || I <- lists:seq(0, 7)]).


store64(N) ->
    << <<((N bsr (8 * I)) rem 256)>> || I <- lists:seq(0, 7) >>.


lotta_zeroes() ->
    <<0:(8 * 200)>>.
