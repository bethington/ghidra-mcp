/*
 * state_machine.c — Archetype: switch-ladder state transition.
 *
 * A lightweight tokenizer-style state machine used as a benchmark for
 * whether fun-doc can recognize and name a state-transition function.
 * Intentionally simple cases: INIT -> IDENT on letters, INIT -> NUMBER
 * on digits, IDENT/NUMBER stay in state while the character class
 * continues, and everything else resets to INIT. The enum + explicit
 * switch is the canonical C idiom that Ghidra's decompiler recovers
 * cleanly as a table or cascade of conditionals.
 */

#include <windows.h>

enum ParserState {
    PARSER_STATE_INIT = 0,
    PARSER_STATE_IDENT = 1,
    PARSER_STATE_NUMBER = 2,
    PARSER_STATE_PUNCT = 3
};

/**
 * Advance the parser state machine one input byte.
 *
 * Given the current state and one input byte, return the next state.
 * Letters advance into IDENT; digits into NUMBER; single punctuation
 * characters (comma, semicolon, period) emit PUNCT; everything else
 * resets to INIT. IDENT / NUMBER stay in-state while the character
 * class continues.
 *
 * @param current_state one of the PARSER_STATE_* enum values
 * @param input         next input byte
 * @return the next state
 */
__declspec(dllexport)
int __stdcall advance_parser_state(int current_state, unsigned char input)
{
    int next_state;

    switch (current_state) {
    case PARSER_STATE_INIT:
        if (input >= 'a' && input <= 'z') {
            next_state = PARSER_STATE_IDENT;
        } else if (input >= '0' && input <= '9') {
            next_state = PARSER_STATE_NUMBER;
        } else if (input == ',' || input == ';' || input == '.') {
            next_state = PARSER_STATE_PUNCT;
        } else {
            next_state = PARSER_STATE_INIT;
        }
        break;

    case PARSER_STATE_IDENT:
        if (input >= 'a' && input <= 'z') {
            next_state = PARSER_STATE_IDENT;
        } else {
            next_state = PARSER_STATE_INIT;
        }
        break;

    case PARSER_STATE_NUMBER:
        if (input >= '0' && input <= '9') {
            next_state = PARSER_STATE_NUMBER;
        } else {
            next_state = PARSER_STATE_INIT;
        }
        break;

    case PARSER_STATE_PUNCT:
    default:
        next_state = PARSER_STATE_INIT;
        break;
    }

    return next_state;
}
