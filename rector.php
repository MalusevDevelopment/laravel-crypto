<?php

declare(strict_types=1);

use Rector\Caching\ValueObject\Storage\FileCacheStorage;
use Rector\CodeQuality\Rector\Class_\DynamicDocBlockPropertyToNativePropertyRector;
use Rector\CodeQuality\Rector\Concat\DirnameDirConcatStringToDirectStringPathRector;
use Rector\CodingStyle\Rector\Assign\NestedTernaryToMatchRector;
use Rector\CodingStyle\Rector\FuncCall\ArraySpreadInsteadOfArrayMergeRector;
use Rector\Config\RectorConfig;
use Rector\Php73\Rector\FuncCall\JsonThrowOnErrorRector;
use Rector\Php80\Rector\NotIdentical\MbStrContainsRector;
use Rector\Php80\Rector\Property\NestedAnnotationToAttributeRector;
use Rector\Php81\Rector\Array_\ArrayToFirstClassCallableRector;
use Rector\Php82\Rector\Param\AddSensitiveParameterAttributeRector;
use Rector\Php84\Rector\Class_\PropertyHookRector;
use Rector\Php85\Rector\Expression\NestedFuncCallsToPipeOperatorRector;
use Rector\Php85\Rector\StmtsAwareInterface\SequentialAssignmentsToPipeOperatorRector;
use Rector\PHPUnit\AnnotationsToAttributes\Rector\Class_\AnnotationWithValueToAttributeRector;
use Rector\Set\ValueObject\SetList;
use Rector\Symfony\Symfony28\Rector\StaticCall\ParseFileRector;
use Rector\Transform\Rector\ArrayDimFetch\ArrayDimFetchToMethodCallRector;
use Rector\Transform\Rector\Attribute\AttributeKeyToClassConstFetchRector;
use Rector\Transform\Rector\ConstFetch\ConstFetchToClassConstFetchRector;
use Rector\Transform\Rector\FuncCall\FuncCallToConstFetchRector;
use Rector\Transform\Rector\MethodCall\MethodCallToFuncCallRector;
use Rector\Transform\Rector\StaticCall\StaticCallToMethodCallRector;
use Rector\Transform\Rector\String_\StringToClassConstantRector;
use Rector\TypeDeclaration\Rector\Property\AddPropertyTypeDeclarationRector;
use Rector\TypeDeclaration\Rector\StmtsAwareInterface\DeclareStrictTypesRector;
use Rector\TypeDeclarationDocblocks\Rector\Class_\AddReturnArrayDocblockFromDataProviderParamRector;
use Rector\TypeDeclarationDocblocks\Rector\Class_\AddReturnDocblockDataProviderRector;
use Rector\TypeDeclarationDocblocks\Rector\Class_\ClassMethodArrayDocblockParamFromLocalCallsRector;
use Rector\TypeDeclarationDocblocks\Rector\Class_\DocblockVarArrayFromGetterReturnRector;
use Rector\TypeDeclarationDocblocks\Rector\Class_\DocblockVarArrayFromPropertyDefaultsRector;
use Rector\TypeDeclarationDocblocks\Rector\Class_\DocblockVarFromParamDocblockInConstructorRector;
use Rector\TypeDeclarationDocblocks\Rector\ClassMethod\AddParamArrayDocblockFromDataProviderRector;
use Rector\TypeDeclarationDocblocks\Rector\ClassMethod\AddReturnDocblockForCommonObjectDenominatorRector;
use Rector\TypeDeclarationDocblocks\Rector\ClassMethod\DocblockReturnArrayFromDirectArrayInstanceRector;
use Rector\ValueObject\PhpVersion;
use RectorLaravel\Rector\Namespace_\FactoryDefinitionRector;
use RectorLaravel\Set\LaravelSetList;
use RectorLaravel\Set\LaravelSetProvider;

return RectorConfig::configure()
    ->withSetProviders(LaravelSetProvider::class)
    ->withSets([
        LaravelSetList::LARAVEL_ARRAYACCESS_TO_METHOD_CALL,
        LaravelSetList::LARAVEL_ARRAY_STR_FUNCTION_TO_STATIC_CALL,
        LaravelSetList::LARAVEL_CODE_QUALITY,
        LaravelSetList::LARAVEL_COLLECTION,
        LaravelSetList::LARAVEL_CONTAINER_STRING_TO_FULLY_QUALIFIED_NAME,
        LaravelSetList::LARAVEL_ELOQUENT_MAGIC_METHOD_TO_QUERY_BUILDER,
        LaravelSetList::LARAVEL_FACADE_ALIASES_TO_FULL_NAMES,
        LaravelSetList::LARAVEL_FACTORIES,
        LaravelSetList::LARAVEL_IF_HELPERS,
        LaravelSetList::LARAVEL_LEGACY_FACTORIES_TO_CLASSES,
        SetList::GMAGICK_TO_IMAGICK,
    // SetList::PHP_85,
    SetList::PHP_84,
        SetList::PHP_83,
        SetList::PHP_82,
        SetList::PHP_81,
        SetList::PHP_80,
        SetList::PHP_74,
        SetList::PHP_73,
        SetList::PHP_72,
        SetList::PHP_71,
        SetList::PHP_70,
    ])
    ->withRules([
        DeclareStrictTypesRector::class,
        PropertyHookRector::class,
        JsonThrowOnErrorRector::class,
    // SequentialAssignmentsToPipeOperatorRector::class,
    // NestedFuncCallsToPipeOperatorRector::class,
    NestedAnnotationToAttributeRector::class,
        MbStrContainsRector::class,
        AddSensitiveParameterAttributeRector::class,
        AddReturnDocblockDataProviderRector::class,
        DocblockVarArrayFromPropertyDefaultsRector::class,
        DocblockVarFromParamDocblockInConstructorRector::class,
        AddReturnArrayDocblockFromDataProviderParamRector::class,
        ClassMethodArrayDocblockParamFromLocalCallsRector::class,
        DocblockVarArrayFromGetterReturnRector::class,
        AddReturnDocblockForCommonObjectDenominatorRector::class,
        AddParamArrayDocblockFromDataProviderRector::class,
        DocblockReturnArrayFromDirectArrayInstanceRector::class,
        MethodCallToFuncCallRector::class,
        FuncCallToConstFetchRector::class,
        StaticCallToMethodCallRector::class,
        AttributeKeyToClassConstFetchRector::class,
        ConstFetchToClassConstFetchRector::class,
        StringToClassConstantRector::class,
        ArrayDimFetchToMethodCallRector::class,
        ArraySpreadInsteadOfArrayMergeRector::class,
        NestedTernaryToMatchRector::class,
        DirnameDirConcatStringToDirectStringPathRector::class,
        DynamicDocBlockPropertyToNativePropertyRector::class,
        AddPropertyTypeDeclarationRector::class,
    // ParseFileRector::class,
    // AnnotationWithValueToAttributeRector::class,
])
    ->withImportNames(
        removeUnusedImports: true,
    )
    ->withComposerBased()
    ->withCache(
        cacheDirectory: '/tmp/rector',
        cacheClass: FileCacheStorage::class,
    )
    ->withPaths([
    __DIR__ . '/src',
    __DIR__ . '/tests',
    __DIR__ . '/config',
    ])
    ->withPreparedSets(
        deadCode: true,
        codeQuality: true,
        typeDeclarations: true,
        privatization: true,
        instanceOf: true,
        earlyReturn: true,
        carbon: true,
        phpunitCodeQuality: true,
    )
    ->withParallel()
    ->withPhpVersion(PhpVersion::PHP_84)
    ->withPhpSets()
    // Skip problematic rules causing scope errors during processing
    // See: ArrayToFirstClassCallableRector failing with Scope not available on Array_ node
    ->withSkip([
        ArrayToFirstClassCallableRector::class,
        FactoryDefinitionRector::class,
    ]);
