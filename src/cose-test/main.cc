#define USE_CBOR_CONTEXT
#include <cstring>
#include <cose/cose.h>
#include <cn-cbor/cn-cbor.h>
#include <iostream>
#include <vector>

using namespace std;


static const uint8_t COSE_KEY[] = {
    0x60, 0x77, 0xaa, 0x8c, 0x62, 0x0d, 0xa7, 0x23,
    0x5a, 0x3e, 0xe5, 0x04, 0xea, 0xec, 0x65, 0x64,
};


static const uint8_t COSE_TOKEN[] = {
    0xd0, 0x83, 0x43, 0xa1, 0x01, 0x01, 0xa1, 0x05,
    0x4c, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02,
    0x03, 0x00, 0x01, 0x02, 0x03, 0x58, 0x32, 0x8a,
    0x3d, 0x60, 0xdf, 0xa7, 0x9f, 0x73, 0x95, 0xfb,
    0x45, 0x95, 0xae, 0x89, 0x47, 0x28, 0x86, 0x40,
    0xa4, 0xe8, 0xcb, 0xa1, 0xee, 0x63, 0x01, 0x6d,
    0xd9, 0x74, 0x4b, 0x24, 0x42, 0x75, 0x06, 0xde,
    0x82, 0xa2, 0x73, 0xc8, 0xfc, 0x5e, 0x21, 0x9c,
    0x05, 0x7c, 0x6f, 0xdf, 0x11, 0x69, 0x9c, 0xc5,
    0x44
};


struct AllocatorContext : cn_cbor_context {
    AllocatorContext() : cn_cbor_context { allocate, release, this } {}

private:
    static const size_t CHUNK_SIZE;

    size_t remaining = 0;
    vector<string> blocks;

    static void * allocate( size_t count, size_t size, void * ptr )
    {
        AllocatorContext * ctx = (AllocatorContext*) ptr;

        const size_t required = count * size;
        if( required > ctx->remaining ) {
            ctx->remaining = max( CHUNK_SIZE, required );
            ctx->blocks.push_back( std::string( ctx->remaining, '\0' ) );
        }

        const size_t pos = ctx->blocks.back().size() - ctx->remaining;
        ctx->remaining -= required;
        return ctx->blocks.back().data() + pos;
    }

    static void release( void * ptr, void * ) {}
};

inline const size_t AllocatorContext::CHUNK_SIZE = 2048;


int
main()
{
    // Create an allocator to use for memory management.
    AllocatorContext ctx;

    // Decode the encoded CBOR object into a COSE Encrypt0 message
    cose_errback err;
    int type = 0;
    auto token = (HCOSE_ENCRYPT) COSE_Decode( COSE_TOKEN, sizeof(COSE_TOKEN),
            &type, COSE_encrypt_object, &ctx, &err);
    if( !token ) {
        cerr << "Failed to load token: " << (int) err.err << endl;
        return 1;
    }

    // Decrypt the Encrypt0 message using a pre-shared key
    if( !COSE_Encrypt_decrypt( token, COSE_KEY, sizeof(COSE_KEY), &err )) {
        cerr << "Failed to decrypt token: " << (int) err.err << endl;
        return 1;
    }

    // Extract the decrypted payload.
    size_t len;
    const uint8_t * data = COSE_Encrypt_GetContent( token, &len, &err );
    if( data && !len ) {
        // NOTE: There is a bug in cose-c in which it returns the correct data
        // but the length is 0.  It just so happens that the data is
        // null-terminated, so we can use strlen.  This is probably unsafe and
        // we should file a bug.
        len = strlen( (char*) data );
    }

    // Decode the decrypted payload
    cn_cbor_errback cn_err;
    cn_cbor * cbor = cn_cbor_decode( data, len, &ctx, &cn_err );
    if( !cbor ) {
        cerr << "Failed to decode decrypted payload: " << (int) cn_err.err << endl;
        return 1;
    }

    // Get the handles to the fields
    auto bip = cn_cbor_mapget_string( cbor, "bip" );
    auto sid = cn_cbor_mapget_string( cbor, "sid" );
    auto exp = cn_cbor_mapget_string( cbor, "exp" );

    // Quick validation...
    if( 
        bip->type != CN_CBOR_TEXT
     || sid->type != CN_CBOR_UINT
     || exp->type != CN_CBOR_UINT
    ) {
        return 1;
    }

    // Output payload content
    cout << "bip: " << string(bip->v.str, bip->length) << endl;
    cout << "sid: " << sid->v.uint << endl;
    cout << "exp: " << exp->v.uint << endl;
    return 0;
}
