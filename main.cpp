
#include <iostream>

namespace enc {

    typedef long long eb_t/*encrypted_buffer_t*/;

    namespace ptr {
        const static eb_t xor_key = 0x34782342435i64; // change this to something else :)
        static eb_t compile_time_key[4] = { 0, 0, 0, 0 };

        __forceinline void* enc( void* pointer ) {
            if ( !pointer ) return nullptr;

            *(eb_t*)( &pointer ) ^= xor_key;
            *(eb_t*)( &pointer ) >> sizeof( int ) * sizeof( pointer );
            *(eb_t*)( &pointer ) += sizeof( eb_t );

            // here what you can do is add more things to make it more confusing for somebody reverse engineering your program or
            // something similar to that.
            // example:

            /*          
            *(eb_t*)(&pointer) &= 0x32;
            *(eb_t*)(&pointer) *= (sizeof(pointer) / sizeof(int)) ^ (xor_key / 2);
            */

            // this isn't the best way to do things (with a static encryption/xor key)
            // but you can use the __TIME__/__TIMESTAMP__ macro to make compile time generated keys.
            // an example of compile time is below :)

            return pointer;
        }

        // compile time generated encryption keys
        __forceinline void* enc_compile_time( void* pointer ) {
            if ( !pointer ) return nullptr;

            *(eb_t*)( &pointer ) ^= xor_key;
            *(eb_t*)( &pointer ) >> sizeof( int ) * sizeof( pointer );
            *(eb_t*)( &pointer ) += sizeof( eb_t );

            // initialize the 4 keys :)
            // __TIME__ changes on every compile (unless you compile in like 1second lol)
            for ( char c : __TIME__ )
            {
                compile_time_key[0] ^= ( (unsigned)c ^ *(eb_t*)(&pointer) ) + 2 ^ 0x278312367i64;
                compile_time_key[1] = (-compile_time_key[0] ^ 20);
                compile_time_key[2] = compile_time_key[1] + 0xFF ^ 0x100 - compile_time_key[1];
                compile_time_key[3] = compile_time_key[2] ^ (4 - 8) & *(eb_t*)(&pointer) + sizeof(compile_time_key);
            }
            
            *(eb_t*)( &pointer ) += compile_time_key[0];
            *(eb_t*)( &pointer ) -= compile_time_key[1];
            *(eb_t*)( &pointer ) += compile_time_key[2];
            *(eb_t*)( &pointer ) -= compile_time_key[3];

            return pointer;
        }

        __forceinline void* dec( void* pointer )
        {
            if ( !pointer ) return nullptr;

            *(eb_t*)( &pointer ) -= sizeof( eb_t );
            *(eb_t*)( &pointer ) << sizeof( int ) * sizeof( pointer );
            *(eb_t*)( &pointer ) ^= xor_key;

            return pointer;
        }

        __forceinline void* dec_compile_time( void* pointer ) 
        {
            if ( !pointer ) return nullptr;

            *(eb_t*)( &pointer ) -= compile_time_key[0];
            *(eb_t*)( &pointer ) += compile_time_key[1];
            *(eb_t*)( &pointer ) -= compile_time_key[2];
            *(eb_t*)( &pointer ) += compile_time_key[3];
            
            *(eb_t*)( &pointer ) -= sizeof( eb_t );
            *(eb_t*)( &pointer ) << sizeof( int ) * sizeof( pointer );
            *(eb_t*)( &pointer ) ^= xor_key;

            return pointer;
        }

        __forceinline void output_compiletime_keys( ) {
            printf( "   -> CompileTime Encryption Key '0': 0x%llx\n" , compile_time_key[0] );
            printf( "   -> CompileTime Encryption Key '1': 0x%llx\n" , compile_time_key[1] );
            printf( "   -> CompileTime Encryption Key '2': 0x%llx\n" , compile_time_key[2] );
            printf( "   -> CompileTime Encryption Key '3': 0x%llx\n" , compile_time_key[3] );
        }
    }
}

int main()
{
    int original = 20;
    int* o_pointer = &original;

    printf( "Original Value: %i\n" , original );
    printf( "Original Pointer: 0x%p\n\n" , o_pointer );

    // This is using compile time generated keys, you can just use: enc::ptr::enc for non-compile time enc keys.
    void* o_pointer_encrypted = enc::ptr::enc_compile_time( o_pointer );

    printf( "Encrypted Pointer: 0x%p\n\n" , o_pointer_encrypted );

    // Compile time generated decryption
    void* decrypted_pointer = enc::ptr::dec_compile_time( o_pointer_encrypted );

    printf( "Decrypted Pointer: 0x%p\n" , decrypted_pointer );

    printf( "Decrypted Pointer Value: %i\n" , *(int*)( decrypted_pointer ) );

    enc::ptr::output_compiletime_keys( );

    while ( 1 ) { }
}

